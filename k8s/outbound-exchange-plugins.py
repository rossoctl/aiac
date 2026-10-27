#!/usr/bin/env python3
"""Count the outbound token-exchange plugins of an AuthBridge runtime config.

Reads an ``authbridge-runtime-config`` ``config.yaml`` on stdin and prints
``token-exchange-aiac=<n> token-exchange=<m>``, counting whole plugin names on
the **outbound** leg only. The wiring is right when it prints ``1`` and ``0``.
It parses the YAML, so quoting, comments and the inbound leg do not change the
count. The system harness applies the same rule (``exchange_plugin_reason`` in
``test/system/launcher.py``).

Used by ``k8s/opa-kind-verify.sh`` (Verify 1) and the onboarding demo driver's
preflight. Requires PyYAML. Exits 2 when stdin is not a YAML mapping.

Usage:
  kubectl get configmap authbridge-runtime-config -n team1 \\
    -o jsonpath='{.data.config\\.yaml}' | python3 k8s/outbound-exchange-plugins.py
"""

import sys

import yaml

try:
    doc = yaml.safe_load(sys.stdin)
except yaml.YAMLError as exc:
    sys.exit(f"config.yaml is not YAML: {exc}")
if not isinstance(doc, dict):
    print("config.yaml is not a YAML mapping", file=sys.stderr)
    sys.exit(2)
pipeline = doc.get("pipeline")
outbound = pipeline.get("outbound") if isinstance(pipeline, dict) else None
plugins = outbound.get("plugins") if isinstance(outbound, dict) else None
names = [p.get("name") for p in plugins or [] if isinstance(p, dict)]
print(f"token-exchange-aiac={names.count('token-exchange-aiac')} token-exchange={names.count('token-exchange')}")
