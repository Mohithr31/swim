#!/usr/bin/env bash
# JOCKY Agent Runner Script — cross-platform .env aware
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Bootstrap a local .env on first run. The same file is used by the server and agent.
if [ ! -f "$ROOT_DIR/.env" ]; then
    if [ ! -f "$ROOT_DIR/.env.example" ]; then
        echo "[JOCKY-AGENT-ERROR] Missing .env.example in $ROOT_DIR" >&2
        exit 1
    fi
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    python3 - "$ROOT_DIR/.env" <<'PYENV'
from pathlib import Path
import secrets
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace("REPLACE_WITH_GENERATED_API_KEY", secrets.token_urlsafe(32), 1)
s = s.replace("REPLACE_WITH_GENERATED_SECRET", secrets.token_urlsafe(32), 1)
p.write_text(s)
PYENV
    chmod 600 "$ROOT_DIR/.env" 2>/dev/null || true
    echo "[JOCKY-AGENT] Created a new local .env with generated credentials."
fi

# Read .env without sourcing it in the shell. This avoids failures caused by
# markdown/comments/special characters and works with normal python-dotenv syntax.
eval "$(python3 - "$ROOT_DIR/.env" <<'PYLOAD'
from pathlib import Path
import shlex, sys
try:
    from dotenv import dotenv_values
except ImportError:
    print('echo "[JOCKY-AGENT-ERROR] python-dotenv is not installed. Run ./setup_linux.sh first." >&2', file=sys.stdout)
    raise SystemExit(2)
vals = dotenv_values(sys.argv[1])
for key, value in vals.items():
    if value is not None:
        print(f'export {key}={shlex.quote(str(value))}')
PYLOAD
)"

SERVER_URL="${JOCKY_SERVER:-http://127.0.0.1:5000}"
if [ -z "${JOCKY_API_KEY:-}" ] || [[ "$JOCKY_API_KEY" == REPLACE_WITH_* ]]; then
    echo "[JOCKY-AGENT-ERROR] JOCKY_API_KEY is empty or still a placeholder in $ROOT_DIR/.env" >&2
    echo "[JOCKY-AGENT] Set the same JOCKY_API_KEY used by the JOCKY server, then retry." >&2
    exit 1
fi

echo "[JOCKY-AGENT] Server: ${SERVER_URL}"
echo "[JOCKY-AGENT] API key loaded from ${ROOT_DIR}/.env"
exec python3 -m agent.jocky_agent --server "${SERVER_URL}" --api-key "${JOCKY_API_KEY}" "$@"
