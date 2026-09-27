JOCKY Cross-Platform Final
==========================

This single package contains the same JOCKY source tree for Linux and Windows.

Linux:
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  python3 -m server.server
  # second terminal:
  python3 -m agent.jocky_agent --server http://127.0.0.1:5000

Windows PowerShell:
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  python -m server.server
  # second PowerShell:
  python -m agent.jocky_agent --server http://127.0.0.1:5000

Windows launcher (optional):
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\agent\run_agent.ps1 -Server "http://127.0.0.1:5000"

The agent selects the platform-specific collector at runtime. The server and
dashboard are shared. All supported collection operations are read-only.
