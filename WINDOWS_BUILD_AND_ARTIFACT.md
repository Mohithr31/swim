# Windows Agent Artifact / GitHub Deployment

File 1 remains the authoritative codebase and CI configuration.

The dashboard expects the Windows native artifact at:

    dist/jocky-agent-windows.exe

On a Linux server, the included Wine build path can recreate the Windows
artifact when Wine and Windows Python are configured. The dashboard must
never embed the API key in frontend JavaScript.

The real `.env` file is intentionally not committed to source control.
Create it locally from `.env.example` and provide the deployment's API key.

For a fresh checkout, build/verify the Windows artifact before using the
Dashboard -> Agent Artifacts -> Windows download action.
