"""The login-client audience warning (PRD D30; agent side only).

Under agent side a tool gets a pass-through CR (D24): AIAC checks nothing on the tool's inbound, and
only AuthBridge ``jwt-validation`` (signature, issuer, ``aud`` = the tool's clientId) protects it.
The operator attaches each workload's audience scope (``agent-<ns>-<workload>-aud``) as a default
scope to each client in its ``PLATFORM_CLIENT_IDS``, so the user tokens of such a login client carry
the tool's clientId in ``aud``, pass the tool's ``jwt-validation`` and reach the tool with no AIAC
check. This is a known limit of agent side; this module makes it visible in the log.

:func:`warn_platform_tool_audiences` reads, through the IdP Configuration Service
(``GET /platform-clients/tool-audiences``), each audience mapper of a platform login client
(``PLATFORM_SOURCE_CLIENTS``, the same list as the D31 subject-scope link) that names a managed
tool, and logs one WARNING for each. It runs at a tool's onboarding (after the build) and at each
Controller start (after the resync).

Under target side it does nothing: the tool's inbound OPA has no platform-client bypass and needs
both the user gate and the calling-agent gate, so such a link grants nothing there. The operator
makes the link for every tool when its ``PLATFORM_CLIENT_IDS`` names the login client, so a warning
under target side would only be noise.

Best effort: a failure (the IdP, an unset realm, an unknown side) is logged as one WARNING and is
never raised, so it cannot fail the onboarding or the start. It refuses nothing.
"""

import logging

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ClientId, PlatformToolAudience
from aiac.policy.computation import enforcement_side
from aiac.policy.model.models import EnforcementSide
from aiac.shared.logging_config import loggable

logger = logging.getLogger(__name__)

_EXPOSED = (
    "login client %r has %s, whose audience mapper %r puts the clientId of the tool %r into aud: under "
    "agent side the tool has a pass-through CR, so a user token of %r passes the tool's jwt-validation "
    "and reaches the tool with no AIAC check (known limit, PRD §6 Known limits (enforcement); D30). "
    "Target side closes this. A link that you remove by hand comes back when the operator reconciles "
    "the workload again (it attaches the audience scope to each client in PLATFORM_CLIENT_IDS)"
)

_READ_FAILED = (
    "cannot read the audience scopes of the platform login clients for %s (agent side): %s. "
    "The login-client audience warning is skipped"
)

_LINK_KINDS = {"default": "a default", "optional": "an optional"}


def warn_platform_tool_audiences(config: Configuration | None = None, tool_client_id: ClientId | None = None) -> None:
    """Under agent side, log one WARNING for each audience mapper of a platform login client that puts a
    managed tool's clientId into ``aud`` (only ``tool_client_id`` when given). Under target side, do
    nothing (no IdP read). Best effort: a failure is logged as a WARNING and never raised.
    ``config`` defaults to ``Configuration.for_default_realm()`` (built inside the guard)."""
    try:
        if enforcement_side() is not EnforcementSide.AGENT_SIDE:
            return
        links = (config or Configuration.for_default_realm()).get_platform_tool_audiences(tool_client_id)
    except Exception as e:  # noqa: BLE001 — the warning must not fail the onboarding or the start
        target = f"the tool {loggable(tool_client_id)!r}" if tool_client_id else "the managed tools"
        logger.warning(_READ_FAILED, target, loggable(e))
        return
    for link in links:
        login_client = loggable(link.login_client)
        logger.warning(
            _EXPOSED,
            login_client,
            _where(link),
            loggable(link.mapper),
            loggable(link.tool_client_id),
            login_client,
        )


def _where(link: PlatformToolAudience) -> str:
    """Where the audience mapper is: in a default or optional client scope, or on the login client."""
    if link.link == "client":
        return "a protocol mapper on its own client"
    return f"the client scope {loggable(link.scope)!r} as {_LINK_KINDS[link.link]} scope"
