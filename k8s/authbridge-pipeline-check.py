#!/usr/bin/env python3
"""Check the plugin wiring of an AuthBridge runtime config.

Reads an ``authbridge-runtime-config`` ``config.yaml`` on stdin, or, with
``--namespace NS``, from the ConfigMap of ``NS`` with ``kubectl`` (its stderr is
kept apart, so a kubectl warning cannot break the parse; a failed read is
reported). Prints ``ok trust_domain=<td>`` when the wiring is right, else one
line that says what is wrong. The wiring is right when:

- ``opa`` runs once on each leg, **after** the plugins that set what AIAC's Rego
  reads there: inbound, ``jwt-validation`` (``input.identity``) and
  ``mcp-parser`` (``input.mcp``, which a tool's inbound package reads); outbound,
  ``token-exchange-aiac`` (``input.identity``, ``input.delegation``). AIAC's
  outbound package is a pass-through (D24) and reads no ``input.mcp``. Other
  parsers may run anywhere: no AIAC policy reads their signals;
- the **outbound** leg runs ``token-exchange-aiac`` once and ``token-exchange``
  not at all;
- that ``token-exchange-aiac`` has an ``audience_template`` of the form
  ``spiffe://<td>/...{namespace}...{service}...`` (``<td>`` is the trust domain
  it exchanges for). Without ``{service}`` it names one audience for every call;
  without ``{namespace}``, every agent namespace the chart renders this one
  pipeline into would derive one namespace's audiences;
- its ``no_token_policy`` is ``deny`` or unset (the plugin default, ``deny``): a
  request with no bearer to a target is refused, never exchanged with the
  workload's own token. ``k8s/opa-kind-enable.sh`` once set
  ``client-credentials``; a cluster still on that overlay must re-run it.

It parses the YAML and reads whole plugin names per leg, in order, so quoting,
comments, the other leg and the bare-string entry form (``- opa``, which cortex
reads as ``{name: opa}``) do not change the verdict; the order of the plugins
does.

The rule lives here once. ``k8s/opa-kind-verify.sh`` (Verify 1), the onboarding
demo driver's preflight and its teardown run this file; the system harness loads
it (``pipeline_check`` in ``test/system/launcher.py``), so they cannot disagree.

``--opa-legs`` prints only the number of legs that run ``opa`` (``0`` to ``2``),
for a status line that must not fail on a cluster that is not wired.

Requires PyYAML. Always prints one line on stdout, also when it fails (a missing
PyYAML, an unexpected error), so a caller can show it. Exits 1 when the wiring is
wrong, the ConfigMap cannot be read or the check fails (never with ``--opa-legs``,
which prints nothing then), 2 on any other argument.

Usage:
  python3 k8s/authbridge-pipeline-check.py --namespace team1
  kubectl get configmap authbridge-runtime-config -n team1 \\
    -o jsonpath='{.data.config\\.yaml}' | python3 k8s/authbridge-pipeline-check.py [--opa-legs]
"""

from __future__ import annotations

import sys

LEGS = ("inbound", "outbound")


def leg_plugins(config_yaml: str) -> dict[str, list[dict]] | None:
    """The plugin entries of each leg of ``config_yaml``, as mappings (``{"inbound": [...],
    "outbound": [...]}``), or ``None`` when ``config_yaml`` is not a YAML mapping. **Pure.** A bare
    string entry is ``{"name": <string>}``, as cortex reads it (``config.PluginEntry``). A leg the config
    does not have, a ``plugins`` that is not a list, or an entry that is neither, gives nothing."""
    import yaml

    try:
        doc = yaml.safe_load(config_yaml)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    pipeline = doc.get("pipeline")
    legs: dict[str, list[dict]] = {}
    for leg in LEGS:
        node = pipeline.get(leg) if isinstance(pipeline, dict) else None
        plugins = node.get("plugins") if isinstance(node, dict) else None
        entries = plugins if isinstance(plugins, list) else []
        legs[leg] = [{"name": p} if isinstance(p, str) else p for p in entries if isinstance(p, (dict, str))]
    return legs


def plugin_names(legs: dict[str, list[dict]]) -> dict[str, list[str]]:
    """The plugin names of each leg of ``legs`` (``leg_plugins``). **Pure.**"""
    return {leg: [p["name"] for p in plugins if isinstance(p.get("name"), str)] for leg, plugins in legs.items()}


def _exchange_config(legs: dict[str, list[dict]]) -> dict:
    """The ``config`` of the outbound ``token-exchange-aiac`` of ``legs``, or ``{}``."""
    for p in legs["outbound"]:
        config = p.get("config")
        if p.get("name") == "token-exchange-aiac" and isinstance(config, dict):
            return config
    return {}


def trust_domain(legs: dict[str, list[dict]]) -> str | None:
    """The SPIFFE trust domain in the ``audience_template`` of the outbound ``token-exchange-aiac`` of
    ``legs`` (``leg_plugins``), or ``None`` when there is none (no such plugin, or a template that is
    not ``spiffe://<td>/...{namespace}...{service}...``). **Pure.**"""
    template = _exchange_config(legs).get("audience_template")
    if not isinstance(template, str) or not template.startswith("spiffe://"):
        return None
    authority, _, path = template[len("spiffe://") :].partition("/")
    # Without ``{service}`` the template names one audience for every call; without ``{namespace}``,
    # the one pipeline the chart renders into every agent namespace derives one namespace's audiences.
    # The operator names a workload ``.../ns/<ns>/sa/<sa>``, so ``{namespace}`` comes first.
    ns_at, svc_at = path.find("{namespace}"), path.find("{service}")
    return authority if authority and 0 <= ns_at < svc_at else None


def problem(legs: dict[str, list[dict]], td: str | None) -> str | None:
    """What is wrong with the wiring of ``legs`` (``leg_plugins``), whose trust domain is ``td``
    (``trust_domain``), or ``None`` when it is right (see the module docstring). **Pure.** Nothing adds
    an outbound route, so only ``token-exchange-aiac`` exchanges the agent's call to the tool, and a
    ``token-exchange`` entry means the pipeline predates the switch."""
    names = plugin_names(legs)
    opa = {leg: names[leg].count("opa") for leg in LEGS}
    if any(n != 1 for n in opa.values()):
        return f"opa per leg: inbound={opa['inbound']}, outbound={opa['outbound']} (want 1 on each leg)"
    new, legacy = names["outbound"].count("token-exchange-aiac"), names["outbound"].count("token-exchange")
    if new != 1 or legacy != 0:
        return (
            f"outbound exchange plugins: token-exchange-aiac={new}, token-exchange={legacy} "
            "(want 1/0; an older pipeline)"
        )
    # OPA must run after the plugins that set what AIAC's Rego reads on that leg, or it decides with
    # them undefined: inbound, input.identity (jwt-validation) and input.mcp (mcp-parser, read by a
    # tool's inbound package); outbound, input.identity (token-exchange-aiac). The outbound package is a
    # pass-through (D24) and reads no input.mcp, and no AIAC policy reads the other parsers' signals
    # (input.a2a, input.inference), so their place is free.
    for leg, needed in (("inbound", ("jwt-validation", "mcp-parser")), ("outbound", ("token-exchange-aiac",))):
        for plugin in needed:
            if plugin not in names[leg]:
                return f"the {leg} leg has no {plugin} (it sets what the {leg} opa reads)"
        late = [n for n in names[leg][names[leg].index("opa") + 1 :] if n in needed]
        if late:
            return f"{leg} plugin order {names[leg]}: opa must run after {' and '.join(needed)}"
    if td is None:
        return (
            "the outbound token-exchange-aiac has no spiffe://<trust-domain>/...{namespace}...{service}... "
            "audience_template"
        )
    # Unset, or an empty value (YAML null, ""): the plugin applies its default, deny. Anything else must
    # be the string "deny" (``false`` or ``0`` is not unset).
    policy = _exchange_config(legs).get("no_token_policy")
    if policy not in (None, "", "deny"):
        return f"the outbound token-exchange-aiac has no_token_policy {policy!r} (want 'deny'; an older overlay)"
    return None


def check(config_yaml: str) -> tuple[str | None, str | None]:
    """``(problem, trust_domain)`` of ``config_yaml``, parsed once. **Pure.** Exactly one of the two is
    set: the trust domain only when the wiring is right."""
    legs = leg_plugins(config_yaml)
    if legs is None:
        return "config.yaml is not a YAML mapping", None
    td = trust_domain(legs)
    wrong = problem(legs, td)
    return (wrong, None) if wrong else (None, td)


def opa_legs(config_yaml: str) -> int:
    """How many legs of ``config_yaml`` run ``opa`` (``0`` when it is not YAML). **Pure.**"""
    legs = leg_plugins(config_yaml)
    return 0 if legs is None else sum("opa" in names for names in plugin_names(legs).values())


def read_config(namespace: str) -> tuple[str | None, str | None]:
    """``(config_yaml, error)`` of ``authbridge-runtime-config`` in ``namespace``, read with ``kubectl``:
    exactly one is set. kubectl's stderr is kept apart from the YAML and only names a failed read."""
    import subprocess

    try:
        run = subprocess.run(
            ["kubectl", "get", "configmap", "authbridge-runtime-config", "-n", namespace,
             "-o", r"jsonpath={.data.config\.yaml}"],
            capture_output=True, text=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"cannot read configmap authbridge-runtime-config in {namespace}: {exc}"
    if run.returncode != 0:
        err = " ".join(run.stderr.split())
        return None, f"cannot read configmap authbridge-runtime-config in {namespace}: {err}"
    if not run.stdout.strip():
        return None, f"configmap authbridge-runtime-config in {namespace} has no config.yaml"
    return run.stdout, None


def main(argv: list[str]) -> int:
    try:
        return _main(argv)
    except Exception as exc:
        # The wiring check always prints a verdict line, so a caller never sees nothing. ``--opa-legs``
        # prints only a count, so it prints nothing, and its caller reports the count as unknown.
        if argv != ["--opa-legs"]:
            print(f"authbridge-pipeline-check.py failed: {type(exc).__name__}: {exc}")
        return 1


def _main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--namespace":
        config_yaml, err = read_config(argv[1])
        if err:
            print(err)
            return 1
    elif argv in ([], ["--opa-legs"]):
        if sys.stdin.isatty():  # no pipe: say how to call it rather than wait on the terminal
            print("usage: authbridge-pipeline-check.py --namespace NS, or pipe config.yaml on stdin", file=sys.stderr)
            return 2
        config_yaml = sys.stdin.read()
    else:
        print(
            f"usage: authbridge-pipeline-check.py [--namespace NS | --opa-legs] (got {' '.join(argv)})", file=sys.stderr
        )
        return 2
    if argv == ["--opa-legs"]:
        print(opa_legs(config_yaml))
        return 0
    wrong, td = check(config_yaml)
    print(wrong or f"ok trust_domain={td}")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
