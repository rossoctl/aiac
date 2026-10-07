# AIAC Keycloak Event Listener

A Keycloak Event Listener SPI that translates Keycloak **admin events** into NATS publishes on
the AIAC Event Broker (see [`../docs/specs/components/event-broker.md`](../docs/specs/components/event-broker.md)
and PRD §7.6 / §7.11). It is a pure publisher — no business logic, same "thin adapter" philosophy
as the AIAC Agent's own NATS consumer (`../src/aiac/agent/eventbus/`).

This module only builds and packages the SPI. It does **not** wire itself into any running
Keycloak deployment — the real Keycloak instance for this platform is deployed by a separate
Helm chart outside this repo. Installing/enabling the listener there is a manual step, documented
below.

## Event → subject mapping

| Keycloak admin event | AIAC subject | Notes |
|---|---|---|
| `CLIENT` + `CREATE` (`CLIENT_CREATED`) | `aiac.apply.service.{internal-uuid}` | id parsed from `resourcePath` (`clients/{uuid}`) — this is the Keycloak *internal* client UUID, which is what `onboard_service()` expects, not the human-readable `clientId`. |
| `REALM_ROLE` / `CLIENT_ROLE` + `CREATE` or `UPDATE` | `aiac.apply.role.{role-name}` | id is the trailing path segment (a role **name**, not a UUID). `update_role()` is currently a stub with no finalized ID contract (UC3 not yet implemented) — revisit this mapping once UC3 lands. |
| everything else (user events, `DELETE`, etc.) | — | dropped; OPA rules are role-scoped and resolve entitlements from the caller's role automatically. |

Payload is always the minimal `{"id": "<entity-id>"}` — the event is a trigger, not a data
carrier; the AIAC Agent pulls all state it needs from the IdP Configuration Service.

`onEvent(Event)` (the legacy user-facing event stream) is a no-op by design — `CLIENT_CREATED`
and role create/update are **admin** events in modern Keycloak, delivered via
`onEvent(AdminEvent, boolean)`.

## Publish after the commit

Keycloak calls `onEvent(AdminEvent, boolean)` synchronously, **before** it commits the change
that the event describes. If the listener published at that time, a subscriber that reads the
entity at once could get `404`: the AIAC Agent reads a new client through the IdP Configuration
Service, on another Keycloak session, and the row is not committed yet. The onboarding then
started only at the JetStream redelivery (`ACK_WAIT`, 600 s).

Thus `onEvent` does not publish. It maps the event to its subject (`SubjectMapper`) and puts the
subject in a queue. At its first matching event, each provider instance enlists one
after-completion transaction (`KeycloakTransactionManager.enlistAfterCompletion`, a small
`AbstractKeycloakTransaction`) into the transaction manager of its session. Keycloak commits that
transaction only after all the main transactions of the session have committed:

| Result of the session | What the listener does |
|---|---|
| Commit | Publishes each queued subject, in event order. |
| Rollback (or a failed commit of a main transaction) | Publishes nothing and discards the queue. A rolled-back create gives no phantom event. Keycloak commits the main transactions one by one and continues after a failure, so if one fails after another one has committed the change, the change can be saved with no event. |
| No active transaction when the event comes | Publishes at once. Keycloak begins an after-completion transaction only when it enlists it into an active manager, so there is no commit to wait for. |

"One transaction" is a rule for each provider instance, not for each session. Keycloak does not
cache the provider on the session: its `AdminEventBuilder` calls the factory's `create(session)`
for each builder that it makes. In practice this is one builder for each admin request, but
`AdminEventBuilder.clone(session)` makes another one (Keycloak 26.5.2 uses it in a partial import
and in a user update). If two providers are on one session, each provider enlists its own
transaction and publishes only its own subjects. Each event is published at most one time.

If an event comes after this provider's transaction has already committed or rolled back (the
admin REST path does not do this), the listener logs the warning
`transaction already finished; dropping event for subject ...` and drops the event. It does not
enlist a second transaction: Keycloak can still be in its after-completion loop, and an enlist at
that time throws out of the manager's commit.

The provider gets the NATS connection at commit time, one time for each commit, not when Keycloak
creates the provider. Keycloak creates a provider for each admin request of a realm that has the
listener, and most requests have no matching event. With the Event Broker down, a connection at
create time would cost a connect attempt for each of these requests.

A publish failure at commit time (no connection, a closed connection, any other runtime error)
does not go to Keycloak. Keycloak's transaction manager throws an after-completion failure to
its caller after the main transactions have committed, so the admin request could fail for a
change that is saved. The listener logs a warning, drops that event and continues with the next
subject. This is the same drop behaviour as before.

## Build

```sh
mvn package          # -> target/aiac-event-listener-0.1.0.jar (shaded — bundles jnats)
mvn test             # SubjectMapperTest + the two AiacEventListenerProvider*Test classes; see Testing below
```

Or via the Makefile: `make package` / `make test`.

## Build the custom Keycloak image

```sh
REGISTRY=ghcr.io/your-org make image   # builds + loads locally
REGISTRY=ghcr.io/your-org make push    # builds + pushes
```

The Dockerfile is a 3-stage build: compile the shaded jar, drop it into
`/opt/keycloak/providers/` and run `kc.sh build` (bakes the augmented server into the image, no
per-pod build at startup), then copy the built distribution into the final runtime image.

## Install

**Jar-only** (existing Keycloak/RHBK deployment):

1. Copy `target/aiac-event-listener-0.1.0.jar` into `/opt/keycloak/providers/`.
2. Run `kc.sh build`.
3. Restart Keycloak.

**Custom image** (this repo does not automate this step — the Keycloak deployment lives in a
separate Helm chart outside this repo):

1. `make push` to publish the image.
2. Override the Keycloak image reference in that chart's values (or Operator CR) to point at
   the pushed image.

## Enable in a realm

The listener is discovered automatically via Java's `ServiceLoader` once the jar is on the
classpath, but it must still be added to the realm's admin-events listener list — either in the
Admin Console (**Realm Settings → Events → Event Listeners**, add `aiac-event-listener`) or via
the Admin REST API:

```sh
curl -X PUT "$KEYCLOAK_URL/admin/realms/$REALM/events/config" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"adminEventsEnabled": true, "eventsListeners": ["jboss-logging", "aiac-event-listener"]}'
```

(`eventsListeners` replaces the whole list — include Keycloak's default `jboss-logging` listener
unless you intend to remove it.)

## Configure `NATS_URL`

Resolved in this order, in `AiacEventListenerProviderFactory.init()`:

1. SPI config value `natsUrl` — settable via the Keycloak SPI env var convention:
   `KC_SPI_EVENTS_LISTENER_AIAC_EVENT_LISTENER_NATS_URL=nats://aiac-event-broker-service:4222`
   (pattern: `KC_SPI_<spi-id>_<provider-id>_<property>`, uppercased, dashes→underscores; the SPI
   id for event listeners is `events-listener`).
2. Plain `NATS_URL` environment variable.
3. Default: `nats://aiac-event-broker-service:4222`.

The factory opens the connection in `postInit()`. If it is not open (the Event Broker was not
reachable, or the client closed it after its reconnect budget), the next commit that has events
to publish tries again.

Setting either on the live Keycloak pod is the separate Helm chart's responsibility, not this
repo's — this code is ready for it either way. Verify the exact SPI env var naming against a
running Keycloak 26.6.3 instance before relying on it in a deploy runbook; it's inferred from
Keycloak's documented CLI-flag-to-env-var convention, not confirmed here.

## Testing

Three unit-test classes, JUnit 5, no Keycloak server:

- `SubjectMapperTest` tests the id parsing and the subject building in isolation, with plain
  JUnit.
- `AiacEventListenerProviderTest` tests the provider with Mockito mocks of `KeycloakSession`,
  `KeycloakTransactionManager` and the jnats `Connection`. It captures the enlisted
  after-completion transaction and drives it through begin/commit or begin/rollback, as
  Keycloak's transaction manager does. It checks: the publish occurs only at commit, never in
  `onEvent`; a rollback publishes nothing; several events of one provider are all published and
  the provider enlists its transaction one time; two providers on one session each enlist their
  own transaction and each event is published one time; the connection is resolved at commit
  time, one time; a non-matching event touches neither the transaction manager nor NATS; a null
  connection, a failed connection lookup or a publish exception at commit does not throw; with
  no active transaction the event is published at once; an event after the provider's transaction
  finished is dropped with the warning and enlists nothing; `onEvent(Event)` is a no-op.
- `AiacEventListenerProviderKeycloakManagerTest` tests the provider with Keycloak's own
  `DefaultKeycloakTransactionManager` (`keycloak-services`, a test-scope dependency with no
  transitive dependency; it is not shaded) and mocked main transactions. It pins the order of the
  real manager: the main transaction commits before the publish; a failed main commit is rethrown
  and publishes nothing; a main commit that fails after another main commit publishes nothing; a
  rollback publishes nothing; an event before the manager begins is published at once; an event
  during the after-completion phase is dropped with the warning, and the commit does not fail.

The factory (`AiacEventListenerProviderFactory`) is thin wiring and has no unit test.

There is no `mvn` on the dev host. Run Maven in the Maven image, from the repository root:

```sh
podman run --rm -v "$PWD/keycloak-spi:/build" -v "$HOME/.m2:/root/.m2" -w /build \
  docker.io/library/maven:3.9-eclipse-temurin-17 mvn -B test      # or: mvn -B package
```

The pom compiles against Keycloak `26.7.3`. To check the code against the Keycloak version that
runs live (for example `26.5.2`), add `-Dkeycloak.version=26.5.2`. The Keycloak classes that the
provider uses (`AbstractKeycloakTransaction`, `KeycloakTransactionManager.enlistAfterCompletion`,
`KeycloakSession.getTransactionManager`) have the same API in `26.5.2` and `26.7.3`. With
`-Dkeycloak.version`, `AiacEventListenerProviderKeycloakManagerTest` uses the transaction manager of
that version; it passes with `26.5.2` and with `26.7.3`.

To verify manually, against a live Keycloak:

1. Build and run the custom image locally (or install the jar into a dev Keycloak).
2. Enable the listener in a realm (see above) and set `NATS_URL` to a reachable broker.
3. `nats sub 'aiac.apply.>'` against that broker.
4. Create a client (or a role) via the Admin Console / REST API and confirm a message appears
   on the expected subject with the expected id. A `GET` of the new client, started when the
   message arrives, must give `200`, not `404`.

## Known gaps / open questions

- **Role ID format is unverified.** `update_role()` in the AIAC Agent is currently a stub with
  no real ID contract — this listener's choice of "role name, not UUID" may need revisiting once
  UC3 (Role Update) is actually implemented.
- **jnats and maven-shade-plugin versions** are pinned to the latest known-stable values as of
  this module's creation — re-check Maven Central before relying on them long-term.
- **SPI env var naming** for the event-listener SPI id (`events-listener`) is inferred from
  Keycloak's documented convention, not confirmed against a running instance.
- **No outbox.** The publish comes after the commit, on the request thread, to core NATS. If the
  listener has no usable NATS connection at that time (it never connected, or the client closed it
  after its reconnect budget), it logs a warning and drops the event. During a short reconnect,
  jnats keeps the publish in its reconnect buffer and sends it after the reconnect. If Keycloak
  stops between the commit and the publish, the event is lost with no log. A partial commit (see
  [Publish after the commit](#publish-after-the-commit)) also gives no event. Recovery: start the
  onboarding by hand (`POST /apply/service/{uuid}` on the Controller).
