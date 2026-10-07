package io.aiac.keycloak.events;

import io.nats.client.Connection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

        verify(transactionManager, times(1)).enlistAfterCompletion(any());
        KeycloakTransaction tx = enlistedTransaction();
        tx.begin();
        verifyNoInteractions(natsConnection);

        tx.commit();
        InOrder inOrder = inOrder(natsConnection);
        inOrder.verify(natsConnection).publish(eq("aiac.apply.service.abc-123"), aryEq(payload("abc-123")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role.editor"), aryEq(payload("editor")));
        inOrder.verify(natsConnection).publish(eq("aiac.apply.role.writer"), aryEq(payload("writer")));
    }

    @Test
    void nonMatchingEventsQueueNothingAndPublishNothing() {
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.UPDATE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.CLIENT, OperationType.DELETE, "clients/abc-123"), false);
        provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.DELETE, "roles/editor"), false);
        provider.onEvent(adminEvent(ResourceType.USER, OperationType.CREATE, "users/some-user"), false);
        provider.onEvent(adminEvent(null, null, null), false);

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
}
