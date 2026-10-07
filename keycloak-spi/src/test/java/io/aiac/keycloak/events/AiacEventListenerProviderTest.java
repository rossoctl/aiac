package io.aiac.keycloak.events;

import io.nats.client.Connection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.KeycloakTransactionManager;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The provider against a mocked Keycloak transaction manager. Keycloak's
 * {@code DefaultKeycloakTransactionManager} commits the after-completion transactions only after
 * every main transaction has committed, and rolls them back instead when one fails; these tests
 * play that role by driving the captured transaction through begin/commit or begin/rollback.
 */
@ExtendWith(MockitoExtension.class)
class AiacEventListenerProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakTransactionManager transactionManager;

    @Mock
    private Connection natsConnection;

    /** The resource path of {@code RoleMapperResource} under {@code UserResource}. */
    static final String ROLE_MAPPING_PATH = "users/user-1/role-mappings/realm";

    /**
     * The representation of a realm-role mapping event: the JSON array of {@code RoleRepresentation}
     * that {@code RoleMapperResource} gives to {@code AdminEventBuilder.representation}.
     */
    static final String TWO_ROLES = "["
            + "{\"id\":\"role-1\",\"name\":\"developer\",\"composite\":false,\"clientRole\":false,"
            + "\"containerId\":\"realm-1\"},"
            + "{\"id\":\"role-2\",\"name\":\"viewer\",\"composite\":false,\"clientRole\":false,"
            + "\"containerId\":\"realm-1\"}]";

    private AiacEventListenerProvider provider;

    @BeforeEach
    void setUp() {
        lenient().when(session.getTransactionManager()).thenReturn(transactionManager);
        lenient().when(transactionManager.isActive()).thenReturn(true);
        provider = new AiacEventListenerProvider(session, () -> natsConnection);
    }

    @Test
    void clientCreatedIsPublishedOnlyAtCommit() {
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        KeycloakTransaction tx = enlistedTransaction();

        tx.begin();
        verifyNoInteractions(natsConnection);

        tx.commit();
        verifyPublished("aiac.apply.service.abc-123", "abc-123");
    }

    @Test
    void rolledBackTransactionPublishesNothing() {
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        KeycloakTransaction tx = enlistedTransaction();

        tx.begin();
        tx.rollback();

        verifyNoInteractions(natsConnection);
    }

    @Test
    void connectionIsResolvedAtCommitNotBefore() {
        AtomicInteger resolved = new AtomicInteger();
        Supplier<Connection> connection = () -> {
            resolved.incrementAndGet();
            return natsConnection;
        };
        provider = new AiacEventListenerProvider(session, connection);

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/editor"), false);
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();
        assertEquals(0, resolved.get());

        tx.commit();
        // One lookup per commit, not one per queued event: with NATS down, each lookup is a
        // connect attempt.
        assertEquals(1, resolved.get());
    }

    @Test
    void twoProvidersOnOneSessionEachEnlistTheirOwnTransaction() {
        // Keycloak does not cache the provider on the session: AdminEventBuilder calls the
        // factory's create(session) for each builder it makes (a new one per admin request, and
        // clone(session) makes another). So "once" holds per provider instance, not per session.
        AiacEventListenerProvider other = new AiacEventListenerProvider(session, () -> natsConnection);

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        other.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/editor"), false);

        ArgumentCaptor<KeycloakTransaction> captor = ArgumentCaptor.forClass(KeycloakTransaction.class);
        verify(transactionManager, times(2)).enlistAfterCompletion(captor.capture());
        for (KeycloakTransaction tx : captor.getAllValues()) {
            tx.begin();
        }
        verifyNoInteractions(natsConnection);

        for (KeycloakTransaction tx : captor.getAllValues()) {
            tx.commit();
        }
        // Each event exactly once: no event lost, none published by both transactions.
        verifyPublished("aiac.apply.service.abc-123", "abc-123");
        verifyPublished("aiac.apply.role.editor", "editor");
    }

    @Test
    void everyEventOfTheProviderIsPublishedAtCommitAndTheTransactionIsEnlistedOnce() {
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/editor"), true);
        provider.onEvent(
                adminEvent(ResourceType.CLIENT_ROLE, OperationType.UPDATE, "clients/abc-123/roles/writer"), false);
        provider.onEvent(roleMapping(OperationType.CREATE, TWO_ROLES), false);

        verify(transactionManager, times(1)).enlistAfterCompletion(any());
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();
        verifyNoInteractions(natsConnection);

        tx.commit();
        InOrder inOrder = inOrder(natsConnection);
        inOrder.verify(natsConnection).publish(eq("aiac.apply.service.abc-123"), aryEq(payload("abc-123")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role.editor"), aryEq(payload("editor")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role.writer"), aryEq(payload("writer")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role-members.role-1"), aryEq(payload("role-1")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role-members.role-2"), aryEq(payload("role-2")));
    }

    @Test
    void nonMatchingEventsQueueNothingAndPublishNothing() {
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.UPDATE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.DELETE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.DELETE, "roles/editor"), false);
        provider.onEvent(adminEvent(ResourceType.USER, OperationType.CREATE, "users/some-user"), false);
        provider.onEvent(adminEvent(null, null, null), false);
        // Known limits: a group mapping, a client-role mapping and a group membership. Each one has a
        // good role list, so the drop comes from the kind or the path, not from the representation.
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE_MAPPING, OperationType.CREATE,
                "groups/group-1/role-mappings/realm", TWO_ROLES), false);
        provider.onEvent(adminEvent(ResourceType.CLIENT_ROLE_MAPPING, OperationType.CREATE,
                "users/user-1/role-mappings/clients/client-1", TWO_ROLES), false);
        provider.onEvent(adminEvent(ResourceType.GROUP_MEMBERSHIP, OperationType.CREATE,
                "users/user-1/groups/group-1", "{\"id\":\"group-1\",\"name\":\"team\"}"), false);

        verifyNoInteractions(transactionManager);
        verifyNoInteractions(natsConnection);
    }

    @Test
    void nullConnectionAtCommitDropsTheEventsWithoutThrowing() {
        provider = new AiacEventListenerProvider(session, () -> null);

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();

        assertDoesNotThrow(tx::commit);
    }

    @Test
    void failingConnectionLookupAtCommitDoesNotThrow() {
        provider = new AiacEventListenerProvider(session, () -> {
            throw new IllegalArgumentException("bad NATS URL");
        });

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();

        assertDoesNotThrow(tx::commit);
    }

    @Test
    void publishFailureAtCommitDoesNotThrowAndDoesNotStopTheOtherEvents() {
        doThrow(new IllegalStateException("Connection is Closed"))
                .when(natsConnection).publish(eq("aiac.apply.service.abc-123"), any(byte[].class));

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/editor"), false);
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();

        assertDoesNotThrow(tx::commit);
        verifyPublished("aiac.apply.role.editor", "editor");
    }

    @Test
    void eventOutsideAnActiveTransactionIsPublishedAtOnce() {
        // Keycloak begins an after-completion transaction only when it is enlisted into an active
        // manager; one enlisted into an inactive manager would never begin, and its commit would
        // throw into the manager. With no transaction to wait for, publish at once.
        when(transactionManager.isActive()).thenReturn(false);

        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);

        verify(transactionManager, never()).enlistAfterCompletion(any());
        verifyPublished("aiac.apply.service.abc-123", "abc-123");
    }

    @Test
    void eventAfterThisProvidersTransactionFinishedIsDroppedWithAWarning() {
        // The manager has committed this provider's transaction but is active again (the admin REST
        // path does not do this). The provider must not enlist a second transaction (the manager
        // can still be in its after-completion loop), and the subject cannot go into the finished
        // transaction: it is dropped with a warning.
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123"), false);
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();
        tx.commit();

        CapturedLog log = CapturedLog.of(AiacEventListenerProvider.class);
        try {
            assertDoesNotThrow(() -> provider.onEvent(
                    adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/second"), false));
            assertTrue(log.hasWarning(
                    "transaction already finished; dropping event for subject aiac.apply.role.second"));
        } finally {
            log.detach();
        }
        verify(transactionManager, times(1)).enlistAfterCompletion(any());
        verify(natsConnection, never()).publish(eq("aiac.apply.role.second"), any(byte[].class));
        verifyPublished("aiac.apply.service.abc-123", "abc-123");
    }

    @Test
    void userRealmRoleAssignPublishesOneSubjectForEachRoleOnlyAtCommit() {
        // includeRepresentation is false (the realm has adminEventsDetailsEnabled = false), but
        // Keycloak sets the representation all the same: the listener does not depend on the flag.
        provider.onEvent(roleMapping(OperationType.CREATE, TWO_ROLES), false);
        KeycloakTransaction tx = enlistedTransaction();

        tx.begin();
        verifyNoInteractions(natsConnection);

        tx.commit();
        InOrder inOrder = inOrder(natsConnection);
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role-members.role-1"), aryEq(payload("role-1")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role-members.role-2"), aryEq(payload("role-2")));
    }

    @Test
    void userRealmRoleUnassignPublishesOneSubjectForEachRoleOnlyAtCommit() {
        provider.onEvent(roleMapping(OperationType.DELETE, TWO_ROLES), true);
        KeycloakTransaction tx = enlistedTransaction();

        tx.begin();
        verifyNoInteractions(natsConnection);

        tx.commit();
        verifyPublished("aiac.apply.role-members.role-1", "role-1");
        verifyPublished("aiac.apply.role-members.role-2", "role-2");
    }

    @Test
    void rolledBackRoleMappingPublishesNothing() {
        provider.onEvent(roleMapping(OperationType.CREATE, TWO_ROLES), false);
        KeycloakTransaction tx = enlistedTransaction();

        tx.begin();
        tx.rollback();

        verifyNoInteractions(natsConnection);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "not json", "{\"id\":\"role-1\"}", "\"role-1\"", "null", "[]"})
    void roleMappingWithNoRoleListIsDroppedWithAWarning(String representation) {
        CapturedLog log = CapturedLog.of(AiacEventListenerProvider.class);
        try {
            assertDoesNotThrow(() -> provider.onEvent(roleMapping(OperationType.CREATE, representation), false));
            assertTrue(log.hasWarning(
                    "role mapping event on " + ROLE_MAPPING_PATH + " has no role list; dropping it"));
        } finally {
            log.detach();
        }
        verifyNoInteractions(transactionManager);
        verifyNoInteractions(natsConnection);
    }

    @Test
    void roleWithNoUsableIdIsDroppedWithAWarningAndTheOtherRolesArePublished() {
        String roles = "[{\"name\":\"no-id\"},{\"id\":\"a.b\",\"name\":\"dotted\"},{\"id\":7},"
                + "\"role-3\",null,{\"id\":\"role-2\",\"name\":\"viewer\"}]";

        CapturedLog log = CapturedLog.of(AiacEventListenerProvider.class);
        try {
            provider.onEvent(roleMapping(OperationType.CREATE, roles), false);
            assertTrue(log.hasWarning("role mapping event on " + ROLE_MAPPING_PATH
                    + " has a role with no usable id; dropping that role: {name=no-id}"));
            assertTrue(log.hasWarning("dropping that role: {id=a.b, name=dotted}"));
            assertTrue(log.hasWarning("dropping that role: {id=7}"));
            assertTrue(log.hasWarning("dropping that role: role-3"));
            assertTrue(log.hasWarning("dropping that role: null"));
        } finally {
            log.detach();
        }
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();
        tx.commit();

        verifyPublished("aiac.apply.role-members.role-2", "role-2");
        verify(natsConnection, times(1)).publish(any(String.class), any(byte[].class));
    }

    @Test
    void roleMappingOutsideAnActiveTransactionIsPublishedAtOnceWithOneConnectionLookup() {
        when(transactionManager.isActive()).thenReturn(false);
        AtomicInteger resolved = new AtomicInteger();
        provider = new AiacEventListenerProvider(session, () -> {
            resolved.incrementAndGet();
            return natsConnection;
        });

        provider.onEvent(roleMapping(OperationType.CREATE, TWO_ROLES), false);

        verify(transactionManager, never()).enlistAfterCompletion(any());
        verifyPublished("aiac.apply.role-members.role-1", "role-1");
        verifyPublished("aiac.apply.role-members.role-2", "role-2");
        assertEquals(1, resolved.get());
    }

    @Test
    void userEventIsANoOp() {
        provider.onEvent(new Event());

        verifyNoInteractions(session);
        verifyNoInteractions(natsConnection);
    }

    private KeycloakTransaction enlistedTransaction() {
        ArgumentCaptor<KeycloakTransaction> captor = ArgumentCaptor.forClass(KeycloakTransaction.class);
        verify(transactionManager).enlistAfterCompletion(captor.capture());
        return captor.getValue();
    }

    private void verifyPublished(String subject, String entityId) {
        verify(natsConnection).publish(eq(subject), aryEq(payload(entityId)));
    }

    static byte[] payload(String entityId) {
        return SubjectMapper.payloadFor(entityId).getBytes(StandardCharsets.UTF_8);
    }

    static AdminEvent adminEvent(ResourceType type, OperationType operation, String resourcePath) {
        AdminEvent event = new AdminEvent();
        event.setResourceType(type);
        event.setOperationType(operation);
        event.setResourcePath(resourcePath);
        return event;
    }

    static AdminEvent adminEvent(
            ResourceType type, OperationType operation, String resourcePath, String representation) {
        AdminEvent event = adminEvent(type, operation, resourcePath);
        event.setRepresentation(representation);
        return event;
    }

    /** A realm-role mapping of a user (or of an agent's service account), as Keycloak sends it. */
    static AdminEvent roleMapping(OperationType operation, String representation) {
        return adminEvent(ResourceType.REALM_ROLE_MAPPING, operation, ROLE_MAPPING_PATH, representation);
    }
}
