#!/bin/bash
# Install the test dependencies so `python3 -m unittest discover -s tests`
# runs in Claude Code on the web sessions. Mirrors .github/workflows/tests.yml.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

python3 -m pip install --quiet --disable-pip-version-check --root-user-action=ignore \
  'jsonschema>=4.23,<5' 'pypdf>=5,<7' 'reportlab>=4,<5' \
  || python3 -m pip install --quiet --disable-pip-version-check --root-user-action=ignore --break-system-packages \
  'jsonschema>=4.23,<5' 'pypdf>=5,<7' 'reportlab>=4,<5'
