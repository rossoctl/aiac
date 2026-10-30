#!/usr/bin/env python3
"""Names the rossoctl operator gives a workload's Keycloak objects, computed as it computes them.

Standard library only. ``demo/use-cases/onboarding/restore.sh`` runs this file; the system harness
loads it (``client_credentials_secret_name`` in ``test/system/uc1_onboard.py``). So the operator's rule
has one copy here, beside the operator's own.

Usage:
  python3 k8s/operator-names.py secret <namespace> <workload>
  python3 k8s/operator-names.py aud-scope <namespace> <workload>
"""

from __future__ import annotations

import hashlib
import sys


def client_credentials_secret_name(namespace: str, workload: str) -> str:
    """The client-credentials Secret the operator writes for ``workload`` in ``namespace``
    (rossoctl/operator ``clientreg.KeycloakClientCredentialsSecretName``: the first 8 bytes of a SHA-256,
    in hex)."""
    key = f"{namespace}\0{workload}\0rossoctl-keycloak-client-credentials"
    return "rossoctl-keycloak-client-credentials-" + hashlib.sha256(key.encode()).hexdigest()[:16]


def aud_scope_name(namespace: str, workload: str) -> str:
    """The audience client scope the operator creates for ``workload`` in ``namespace`` (rossoctl/operator
    ``keycloak.AudienceScopeName`` of the client name ``<namespace>/<workload>``)."""
    return f"agent-{namespace}-{workload}-aud"


_COMMANDS = {"secret": client_credentials_secret_name, "aud-scope": aud_scope_name}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] not in _COMMANDS:
        print(f"usage: operator-names.py {{{'|'.join(_COMMANDS)}}} <namespace> <workload>", file=sys.stderr)
        return 2
    print(_COMMANDS[argv[0]](argv[1], argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
