package io.aiac.keycloak.events;

import static io.aiac.keycloak.events.AiacEventListenerProviderTest.adminEvent;
import static io.aiac.keycloak.events.AiacEventListenerProviderTest.payload;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import io.nats.client.Connection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.services.DefaultKeycloakTransactionManager;
import org.keycloak.tracing.NoopTracingProvider;
import org.keycloak.tracing.TracingProvider;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The provider against Keycloak's own {@code DefaultKeycloakTransactionManager} (keycloak-services,
 * test scope), not a mock. {@link AiacEventListenerProviderTest} drives the enlisted transaction by
 * hand; these tests pin the order of the real manager that the publish after the commit (D33)
 * depends on: it commits the main transactions first and the after-completion transactions after
 * them, and when a main commit fails it rolls the after-completion transactions back. The main
 * transactions are Mockito mocks, in place of the JPA/JTA transaction of a real request.
 */
@ExtendWith(MockitoExtension.class)
class AiacEventListenerProviderKeycloakManagerTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private Connection natsConnection;

    @Mock
    private KeycloakTransaction mainTransaction;

    @Mock
    private KeycloakTransaction laterMainTransaction;

    private DefaultKeycloakTransactionManager transactionManager;

    private AiacEventListenerProvider provider;

    @BeforeEach
    void setUp() {
        transactionManager = new DefaultKeycloakTransactionManager(session);
        lenient().when(session.getTransactionManager()).thenReturn(transactionManager);
        // The manager traces each commit and rollback. begin() also asks the session for a JTA
        // lookup; the mock answers null, so no JTA transaction is enlisted.
        lenient().when(session.getProvider(TracingProvider.class)).thenReturn(new NoopTracingProvider());
        provider = new AiacEventListenerProvider(session, () -> natsConnection);
    }

    @Test
    void theMainTransactionCommitsBeforeThePublish() {
        transactionManager.begin();
        transactionManager.enlist(mainTransaction);
        provider.onEvent(clientCreated(), false);
        verifyNoInteractions(natsConnection);

        transactionManager.commit();

        InOrder order = inOrder(mainTransaction, natsConnection);
        order.verify(mainTransaction).commit();
        order.verify(natsConnection).publish(eq("aiac.apply.service.abc-123"), aryEq(payload("abc-123")));
    }

    @Test
    void aFailedMainCommitIsRethrownAndPublishesNothing() {
        RuntimeException failure = new IllegalStateException("main commit failed");
        doThrow(failure).when(mainTransaction).commit();
        transactionManager.begin();
        transactionManager.enlist(mainTransaction);
        provider.onEvent(clientCreated(), false);

        assertSame(failure, assertThrows(RuntimeException.class, transactionManager::commit));

        verifyNoInteractions(natsConnection);
    }

    @Test
    void aMainCommitThatFailsAfterAnotherMainCommitPublishesNothing() {
        // Keycloak commits the main transactions one by one and keeps going after a failure. When a
        // later one fails, the change of an earlier one can be saved, but the after-completion
        // transactions are rolled back: the change has no event (a manual onboarding recovers it).
        RuntimeException failure = new IllegalStateException("later main commit failed");
        doThrow(failure).when(laterMainTransaction).commit();
        transactionManager.begin();
        transactionManager.enlist(mainTransaction);
        transactionManager.enlist(laterMainTransaction);
        provider.onEvent(clientCreated(), false);

        assertSame(failure, assertThrows(RuntimeException.class, transactionManager::commit));

        verify(mainTransaction).commit();
        verifyNoInteractions(natsConnection);
    }

    @Test
    void aRollbackPublishesNothing() {
        transactionManager.begin();
        transactionManager.enlist(mainTransaction);
        provider.onEvent(clientCreated(), false);

        transactionManager.rollback();

        verify(mainTransaction).rollback();
        verify(mainTransaction, never()).commit();
        verifyNoInteractions(natsConnection);
    }

    @Test
    void anEventBeforeTheManagerBeginsIsPublishedAtOnce() {
        provider.onEvent(clientCreated(), false);

        verify(natsConnection).publish(eq("aiac.apply.service.abc-123"), aryEq(payload("abc-123")));
    }

    @Test
    void anEventDuringTheAfterCompletionPhaseIsDroppedWithAWarningAndTheCommitDoesNotFail() {
        // An event that comes after this provider's transaction has committed, while the manager
        // still commits a later after-completion transaction. The admin REST path does not do this.
        // A second enlist at that time would throw out of the manager's commit (Keycloak 26.7:
        // "Transaction already completed"; 26.5: a ConcurrentModificationException).
        transactionManager.begin();
        provider.onEvent(clientCreated(), false);
        transactionManager.enlistAfterCompletion(new AbstractKeycloakTransaction() {
            @Override
            protected void commitImpl() {
                provider.onEvent(adminEvent(ResourceType.REALM_ROLE, OperationType.CREATE, "roles/late"), false);
            }

            @Override
            protected void rollbackImpl() {
                // Nothing to undo.
            }
        });

        CapturedLog log = CapturedLog.of(AiacEventListenerProvider.class);
        try {
            assertDoesNotThrow(transactionManager::commit);
            assertTrue(log.hasWarning(
                    "transaction already finished; dropping event for subject aiac.apply.role.late"));
        } finally {
            log.detach();
        }
        verify(natsConnection).publish(eq("aiac.apply.service.abc-123"), aryEq(payload("abc-123")));
        verify(natsConnection, never()).publish(eq("aiac.apply.role.late"), any(byte[].class));
    }

    private static AdminEvent clientCreated() {
        return adminEvent(ResourceType.CLIENT, OperationType.CREATE, "clients/abc-123");
    }
}
