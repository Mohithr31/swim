# JOCKY Windows + Linux Deployment

This package keeps the JOCKY V5 project and dashboard as the base and adds the
Wine Windows-agent build helper.

## Linux server

Install Wine and the Windows Python/PyInstaller build prerequisites required by
`server/build_wine_windows.py`.

Then run:

    chmod +x server/build_windows_agent_wine.sh
    ./server/build_windows_agent_wine.sh

The resulting native Windows executable can then be supplied to the Windows
endpoint.

## Linux endpoint

Use the existing native Linux agent/build flow in the V5 project.

## Important

The V5 dashboard, collector/runtime code, database, and existing server logic
are retained as the base. The Wine helper is additive; it does not replace the
V5 server implementation.
