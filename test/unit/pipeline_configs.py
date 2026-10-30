"""The AuthBridge runtime configs the wiring-check tests share — test data, no tests.

``test/unit/test_launcher_outcome.py`` checks the system lane's skip gate on them, and
``test/unit/k8s/test_shared_scripts.py`` checks that ``k8s/authbridge-pipeline-check.py``, run as the
shell scripts run it, gives the same verdict. One list, so the two cannot test different cases.
"""

# ``authbridge-runtime-config`` as ``k8s/opa-kind-enable.sh`` renders it.
CONFIG = """pipeline:
  inbound:
    plugins:
      - name: mcp-parser
      - name: jwt-validation
      - name: opa
  outbound:
    plugins:
      - name: mcp-parser
      - name: token-exchange-aiac
        config:
          audience_template: "spiffe://localtest.me/ns/{namespace}/sa/{service}"
          namespace_file: /var/run/secrets/kubernetes.io/serviceaccount/namespace
      - name: opa
"""
AIAC_ENTRY = (
    "      - name: token-exchange-aiac\n        config:\n"
    '          audience_template: "spiffe://localtest.me/ns/{namespace}/sa/{service}"\n'
    "          namespace_file: /var/run/secrets/kubernetes.io/serviceaccount/namespace\n"
)

TEMPLATE = '"spiffe://localtest.me/ns/{namespace}/sa/{service}"'

# Configs the check passes.
PASSING = [
    CONFIG,
    CONFIG.replace("          namespace_file:", '          no_token_policy: "deny"\n          namespace_file:'),
    # an empty value: the plugin applies its default, deny
    CONFIG.replace("          namespace_file:", "          no_token_policy:\n          namespace_file:"),
    CONFIG.replace("name: token-exchange-aiac", 'name: "token-exchange-aiac"'),
    CONFIG.replace("name: opa", 'name: "opa"'),
    CONFIG + "# - name: token-exchange\n# - name: opa\n",  # a comment is not a plugin
    # bare-string entries, which cortex reads as {name: <string>}
    CONFIG.replace("      - name: jwt-validation\n      - name: opa\n", "      - jwt-validation\n      - opa\n"),
    CONFIG.replace("      - name: mcp-parser\n", "      - mcp-parser\n").replace(
        AIAC_ENTRY + "      - name: opa\n", AIAC_ENTRY + "      - opa\n"
    ),
]

# Configs the check rejects; each changes CONFIG.
SKIPPING = [
    # opa before the plugin that sets its identity: OPA decides with no input.identity / input.delegation
    CONFIG.replace(AIAC_ENTRY + "      - name: opa\n", "      - name: opa\n" + AIAC_ENTRY),
    CONFIG.replace(
        "      - name: jwt-validation\n      - name: opa\n", "      - name: opa\n      - name: jwt-validation\n"
    ),
    # inbound: mcp-parser after opa, or a second jwt-validation after it
    CONFIG.replace(
        "      - name: mcp-parser\n      - name: jwt-validation\n      - name: opa\n",
        "      - name: jwt-validation\n      - name: opa\n      - name: mcp-parser\n",
    ),
    CONFIG.replace(
        "      - name: jwt-validation\n      - name: opa\n",
        "      - name: jwt-validation\n      - name: opa\n      - name: jwt-validation\n",
    ),
    # no mcp-parser inbound: input.mcp, which a tool's inbound package reads, is undefined
    CONFIG.replace(
        "    plugins:\n      - name: mcp-parser\n      - name: jwt-validation\n",
        "    plugins:\n      - name: jwt-validation\n",
    ),
    # no jwt-validation inbound at all
    CONFIG.replace("      - name: jwt-validation\n      - name: opa\n", "      - name: opa\n"),
    # a template without {namespace}: every agent namespace would derive one namespace's audiences
    CONFIG.replace(
        '"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"spiffe://localtest.me/ns/team1/sa/{service}"'
    ),
    CONFIG.replace('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"spiffe://localtest.me/sa/{service}"'),
    # {namespace} after {service}: matches no operator-registered client (.../ns/<ns>/sa/<sa>)
    CONFIG.replace(
        '"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"spiffe://localtest.me/sa/{service}/ns/{namespace}"'
    ),
    CONFIG.replace("name: token-exchange-aiac", "name: token-exchange"),  # an older pipeline
    CONFIG.replace(AIAC_ENTRY, AIAC_ENTRY + "      - name: token-exchange\n"),  # half migrated
    CONFIG.replace(AIAC_ENTRY, AIAC_ENTRY + AIAC_ENTRY),  # duplicated
    # only on the inbound leg, where it exchanges nothing the harness sends
    CONFIG.replace(AIAC_ENTRY, "").replace(
        "      - name: jwt-validation\n", "      - name: jwt-validation\n" + AIAC_ENTRY
    ),
    # opa twice on the outbound leg and not on the inbound leg: still two by substring
    CONFIG.replace("      - name: jwt-validation\n      - name: opa\n", "      - name: jwt-validation\n").replace(
        AIAC_ENTRY + "      - name: opa\n", AIAC_ENTRY + "      - name: opa\n      - name: opa\n"
    ),
    CONFIG.replace(
        "      - name: jwt-validation\n      - name: opa\n", "      - name: jwt-validation\n"
    ),  # no inbound opa
    # a ``plugins`` that is not a list gives no plugins on that leg, never a crash
    CONFIG.replace(
        "  inbound:\n    plugins:\n      - name: mcp-parser\n      - name: jwt-validation\n      - name: opa\n",
        "  inbound:\n    plugins: 3\n",
    ),
    # a falsy no_token_policy is not unset
    CONFIG.replace("          namespace_file:", "          no_token_policy: false\n          namespace_file:"),
    CONFIG.replace("          namespace_file:", "          no_token_policy: 0\n          namespace_file:"),
    # a template with no path names no service: every call would exchange for one audience
    CONFIG.replace('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"spiffe://localtest.me"'),
    CONFIG.replace('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"spiffe://localtest.me/"'),
    # an audience template that names no trust domain
    CONFIG.replace('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', '"{service}"'),
    # the overlay before the switch to deny: a bearer-less call is exchanged with the workload's own token
    CONFIG.replace(
        "          namespace_file:", '          no_token_policy: "client-credentials"\n          namespace_file:'
    ),
    CONFIG.replace("          namespace_file:", '          no_token_policy: "allow"\n          namespace_file:'),
    "pipeline: 3",  # a mapping with no legs
    "",
]
