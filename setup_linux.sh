#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
    cp .env.example .env
    python3 - .env <<'PYENV'
from pathlib import Path
import secrets
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace("REPLACE_WITH_GENERATED_API_KEY", secrets.token_urlsafe(32), 1)
s = s.replace("REPLACE_WITH_GENERATED_SECRET", secrets.token_urlsafe(32), 1)
p.write_text(s)
PYENV
    chmod 600 .env 2>/dev/null || true
    echo "[JOCKY] Created .env with generated local credentials."
else
    echo "[JOCKY] Existing .env preserved."
fi

python3 -m venv .venv-linux
source .venv-linux/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m py_compile server/server.py agent/jocky_agent.py
printf '
[JOCKY] Linux environment ready. Run ./run_server.sh and ./run_agent.sh
'
