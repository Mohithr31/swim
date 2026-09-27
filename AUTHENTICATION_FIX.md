# JOCKY Authentication Fix

The package keeps agent API authentication with `X-API-Key` and adds a
server-side browser session for the dashboard. The API key is not embedded in
dashboard JavaScript.

Start:
```bash
./run_server.sh
```

Open `http://SERVER_IP:5000/` and sign in with the configured dashboard key.

Linux agent:
```bash
python3 agent/jocky_agent.py --server "http://SERVER_IP:5000" --api-key "$JOCKY_API_KEY"
```

Windows agent:
```powershell
$env:JOCKY_API_KEY="YOUR_KEY"
.\jocky-agent-windows.exe --server "http://SERVER_IP:5000" --api-key $env:JOCKY_API_KEY
```

On Linux, the dashboard Windows build action can use
`server/build_wine_windows.py` when Wine is installed.
