# shellcheck shell=bash
# Sourced, not run. Sets YAML_PYTHON to a Python interpreter that can import PyYAML, for the scripts
# that parse YAML (k8s/opa-kind-enable.sh, k8s/opa-kind-verify.sh, the onboarding demo driver):
#   1. $YAML_PYTHON, when the caller set it;
#   2. python3 on PATH, when it has PyYAML;
#   3. the repo's .venv/bin/python (the project venv installs PyYAML).
# Leaves YAML_PYTHON empty when none can, so the caller can stop with its own message.
#
# Usage: . "<repo>/k8s/yaml-python.sh" "<repo root>"

_yaml_python_root="${1:?usage: . k8s/yaml-python.sh <repo root>}"
if [ -n "${YAML_PYTHON:-}" ] && "$YAML_PYTHON" -c 'import yaml' >/dev/null 2>&1; then
  :
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
  YAML_PYTHON=python3
elif [ -x "${_yaml_python_root}/.venv/bin/python" ] \
  && "${_yaml_python_root}/.venv/bin/python" -c 'import yaml' >/dev/null 2>&1; then
  YAML_PYTHON="${_yaml_python_root}/.venv/bin/python"
else
  YAML_PYTHON=""
fi
unset _yaml_python_root
