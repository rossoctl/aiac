"""The committed digested-policy corpus for the eval suites.

``eval/scenarios/*.md`` and ``eval/scenarios_perturbed/*.md`` are raw source prose. Production
feeds the PRB only digested policy (see ``docs/specs/digested-policy.md`` and the PRB spec's
"digested input retires exclusivity handling and Door B" decision), so every eval suite except
``test_policy_pipeline_faithfulness.py`` (which specifically tests the digester itself against the
source) runs against this package's digested ``.md`` files instead of a scenario's own source
directory. The files here are produced once, out of band, by ``convert_scenarios.py`` and committed
— never digested live on a suite's critical path.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

_HERE = Path(__file__).resolve().parent


def digested_policy_path(scenario: ModuleType) -> Path:
    """The committed digested policy file for ``scenario`` — same filename as the scenario's own
    ``POLICY_FILE``, but resolved into this package's directory instead of the scenario module's
    own (which holds the source, not the digest)."""
    return _HERE / scenario.POLICY_FILE
