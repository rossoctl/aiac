package io.aiac.keycloak.events;

import io.nats.client.Connection;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.AbstractKeycloakTransaction.TransactionState;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Thin publisher: on a matching admin event, publishes a minimal {@code {"id": "..."}} payload
 * to the corresponding AIAC subject. {@code CLIENT_CREATED} and role create/update are admin
 * events in modern Keycloak (resourceType/operationType), not the legacy user-facing
 * {@code EventType} enum — so {@link #onEvent(Event)} is a no-op by design (drops
 * REGISTER/UPDATE_PROFILE/etc.; OPA rules are role-scoped and resolve entitlements from the
 * caller's role automatically).
 *
 * <p>A realm-role mapping of a user (or of an agent's service account) is the one event with more
 * than one subject: the provider reads the role ids from the event representation and publishes
 * one {@code aiac.apply.role-members.{role-id}} for each role (see {@link #roleMembersSubjects}).
 *
 * <p><b>Publish after commit.</b> Keycloak calls {@link #onEvent(AdminEvent, boolean)}
 * synchronously, before it commits the change the event describes. A subscriber that reads the
 * entity back at once (the AIAC Agent reads a new client through the IdP Configuration Service)
 * would then get a 404. So {@code onEvent} only maps and queues the subject; the publish happens
 * from an after-completion transaction ({@link PublishAfterCommit}), which Keycloak commits only
 * after every main transaction of the session has committed. A rolled-back session publishes
 * nothing.
 */
public class AiacEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(AiacEventListenerProvider.class);

    private final KeycloakSession session;
    private final Supplier<Connection> natsConnection;

    /**
     * Enlisted on the first matching event, so a request with no matching event enlists nothing.
     * One per provider instance, not one per session: Keycloak does not cache this provider on
     * the session. Its {@code AdminEventBuilder} calls the factory's {@code create(session)} for
     * each builder it makes (in practice, one per admin request; {@code clone(session)} makes
     * another). Two providers on one session each enlist their own transaction and publish only
     * their own subjects.
     */
    private PublishAfterCommit pending;

    /**
     * @param natsConnection resolved at commit time, not here — see
     *                       {@code AiacEventListenerProviderFactory#create}
     */
    public AiacEventListenerProvider(KeycloakSession session, Supplier<Connection> natsConnection) {
        this.session = session;
        this.natsConnection = natsConnection;
    }

    @Override
    public void onEvent(Event event) {
        // No-op — see class javadoc.
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        SubjectMapper.ResourceKind kind = toResourceKind(event.getResourceType());
        String operationType = event.getOperationType() == null ? null : event.getOperationType().name();

        if (SubjectMapper.isUserRealmRoleMapping(kind, operationType, event.getResourcePath())) {
            // Not gated on includeRepresentation. Keycloak's AdminEventBuilder.representation(...)
            // always sets the representation on the event; the flag is only the realm's
            // adminEventsDetailsEnabled (whether the event store keeps the representation).
            queue(roleMembersSubjects(event));
            return;
        }
        SubjectMapper.subjectFor(kind, operationType, event.getResourcePath()).ifPresent(s -> queue(List.of(s)));
    }

    @Override
    public void close() {
        // No-op: the NATS connection is shared across every provider instance the factory
        // creates, and is owned/closed by the factory (postInit/close), not here.
    }

    /**
     * One {@code aiac.apply.role-members.{role-id}} subject for each role in the representation of
     * a realm-role mapping event. Keycloak's {@code RoleMapperResource} gives the roles that it
     * mapped or unmapped as the representation: a JSON array of {@code RoleRepresentation}, each
     * with {@code id} and {@code name}. Only the {@code id} is read, so a field that a later
     * Keycloak adds does not break the parse. A missing, empty or bad representation, or a role
     * with no usable id, is logged and dropped: the Controller resync repairs a missed event.
     */
    private static List<String> roleMembersSubjects(AdminEvent event) {
        String resourcePath = event.getResourcePath();
        List<?> roles = parseJsonArray(event.getRepresentation());
        if (roles == null || roles.isEmpty()) {
            log.warnf("role mapping event on %s has no role list; dropping it", resourcePath);
            return List.of();
        }
        List<String> subjects = new ArrayList<>();
        for (Object role : roles) {
            Object id = role instanceof Map ? ((Map<?, ?>) role).get("id") : null;
            Optional<String> subject =
                    id instanceof String ? SubjectMapper.roleMembersSubject((String) id) : Optional.empty();
            if (subject.isPresent()) {
                subjects.add(subject.get());
            } else {
                log.warnf("role mapping event on %s has a role with no usable id; dropping that role: %s",
                        resourcePath, role);
            }
        }
        return subjects;
    }

    /**
     * The JSON array in {@code json}, as a list of plain maps, strings, numbers and nulls; or null
     * when {@code json} is null, is not JSON, or is not an array. Keycloak's own
     * {@link JsonSerialization} (keycloak-core, on Keycloak's runtime classpath) does the parse, so
     * the shaded jar gets no JSON library.
     */
    private static List<?> parseJsonArray(String json) {
        if (json == null) {
            return null;
        }
        try {
            return JsonSerialization.readValue(json, List.class);
        } catch (IOException e) {
            return null;
        }
    }

    /** Queues the subjects of one event; with no active transaction, publishes them at once. */
    private void queue(List<String> subjects) {
        if (subjects.isEmpty()) {
            return;
        }
        KeycloakTransactionManager transactionManager = session.getTransactionManager();
        if (!transactionManager.isActive()) {
            // Keycloak begins an after-completion transaction only when it is enlisted into an
            // active manager; one enlisted into an inactive manager never begins, and its commit
            // would throw into the manager. With no transaction to wait for, publish at once.
            publishAll(subjects);
            return;
        }
        if (pending == null) {
            pending = new PublishAfterCommit();
            transactionManager.enlistAfterCompletion(pending);
        } else if (pending.getState() == TransactionState.FINISHED) {
            // The manager has already committed or rolled back this provider's transaction, but
            // it is active again. The admin REST path does not do this. A subject added to a
            // finished transaction is never published, so make the loss visible, as for the other
            // drops. Do not enlist a new transaction here: the manager can still be in its
            // after-completion loop, and an add to that list during the loop would throw out of
            // the manager's commit.
            for (String subject : subjects) {
                log.warnf("transaction already finished; dropping event for subject %s", subject);
            }
            return;
        }
        pending.subjects.addAll(subjects);
    }

    /**
     * Never throws: Keycloak's transaction manager rethrows an after-completion failure to the
     * caller after the main transactions have already committed, so the admin request would fail
     * for a change that is in fact saved. A failed publish is logged and dropped, as before.
     */
    private void publishAll(List<String> subjects) {
        // One lookup per commit, not one per subject: with NATS down, each lookup is a connect
        // attempt (see AiacEventListenerProviderFactory#connection).
        Connection connection = null;
        try {
            connection = natsConnection.get();
        } catch (RuntimeException e) {
            log.warn("could not get a NATS connection", e);
        }
        for (String subject : subjects) {
            publish(connection, subject);
        }
    }

    private static void publish(Connection connection, String subject) {
        if (connection == null) {
            log.warnf("NATS connection unavailable; dropping event for subject %s", subject);
            return;
        }
        // Subjects are always "aiac.apply.<type>.<id>" and ids never contain '.' (a client UUID,
        // an encoded role name, or a role id: a role id is a UUID, and SubjectMapper gives no
        // subject for an id with a '.'), so the trailing segment after the last '.' is exactly the
        // id SubjectMapper built the subject from.
        String entityId = subject.substring(subject.lastIndexOf('.') + 1);
        String payload = SubjectMapper.payloadFor(entityId);
        try {
            connection.publish(subject, payload.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            log.warnf(e, "NATS publish failed; dropping event for subject %s", subject);
        }
    }

    private static SubjectMapper.ResourceKind toResourceKind(ResourceType resourceType) {
        if (resourceType == null) {
            return SubjectMapper.ResourceKind.OTHER;
        }
        switch (resourceType) {
            case CLIENT:
                return SubjectMapper.ResourceKind.CLIENT;
            case REALM_ROLE:
                return SubjectMapper.ResourceKind.REALM_ROLE;
            case CLIENT_ROLE:
                return SubjectMapper.ResourceKind.CLIENT_ROLE;
            case REALM_ROLE_MAPPING:
                return SubjectMapper.ResourceKind.REALM_ROLE_MAPPING;
            default:
                return SubjectMapper.ResourceKind.OTHER;
        }
    }

    /**
     * After-completion transaction ({@code KeycloakTransactionManager#enlistAfterCompletion}):
     * Keycloak commits it only after every main transaction of the session has committed, and
     * rolls it back instead when one of them fails. It holds the mapped subjects only, not the
     * {@link AdminEvent}s, so nothing depends on the event objects after {@code onEvent} returns.
     * Built on the public {@link AbstractKeycloakTransaction} (server-spi) rather than
     * {@code org.keycloak.events.EventListenerTransaction} (server-spi-private), which queues the
     * events themselves.
     */
    private final class PublishAfterCommit extends AbstractKeycloakTransaction {

        private final List<String> subjects = new ArrayList<>();

        @Override
        protected void commitImpl() {
            publishAll(subjects);
            subjects.clear();
        }

        @Override
        protected void rollbackImpl() {
            log.debugf("transaction rolled back; dropping %d event(s)", subjects.size());
            subjects.clear();
        }
    }
}
