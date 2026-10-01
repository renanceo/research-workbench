#!/bin/bash
# Install the runtime dependencies declared in pyproject.toml so
# `python3 -m unittest discover -s tests` runs in Claude Code on the web
# sessions. Reads the same declaration CI installs from, so cloud sessions
# and CI test the same versions.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

mapfile -t deps < <(python3 -c '
import tomllib
with open("pyproject.toml", "rb") as f:
    print("\n".join(tomllib.load(f)["project"]["dependencies"]))
')

pip_args=(--quiet --disable-pip-version-check --root-user-action=ignore)
python3 -m pip install "${pip_args[@]}" "${deps[@]}" \
  || python3 -m pip install "${pip_args[@]}" --break-system-packages "${deps[@]}"
