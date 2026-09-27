#!/usr/bin/env bash
# JOCKY Agent Runner Script (agent/ directory)
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/run_agent.sh" "$@"
