# TinyFish + VS Code Starter

This folder is a starter workspace for connecting the hosted TinyFish MCP server to VS Code.

## Included

- `.vscode/mcp.json` — VS Code MCP server configuration for TinyFish.
- `prompts/verify-tinyfish.md` — a safe prompt to test the connection.
- `.gitignore` — ignores common local secrets and environment files.

## Setup

1. Extract this ZIP somewhere convenient.
2. Open the extracted `tinyfish-vscode-starter` folder in VS Code (`File > Open Folder`).
3. Make sure VS Code is up to date and GitHub Copilot Chat / Agent mode is available in your installation.
4. Open `.vscode/mcp.json` and confirm the TinyFish URL is `https://agent.tinyfish.ai/mcp`.
5. Open the Command Palette (`Ctrl+Shift+P`) and look for `MCP: List Servers`.
6. Select `tinyfish` and start it if prompted. If VS Code requests authentication, follow the on-screen flow.
7. Open Copilot Chat in Agent mode and use the test prompt in `prompts/verify-tinyfish.md`.

## Important security note

Do not put your API key in this folder, in `mcp.json`, in a prompt, or in source control. Your previous key was exposed in chat; revoke it and create a replacement. The hosted MCP connection may use a separate sign-in/authentication flow from the Search API key.

## Troubleshooting

- **No MCP commands:** update VS Code and confirm MCP support is available in your installed version and that Copilot Chat is installed/enabled.
- **TinyFish is listed but won't start:** open the MCP server output/logs in VS Code and read the exact error.
- **Authentication prompt:** complete the flow shown by VS Code; don't paste secrets into chat.
- **Tool doesn't appear in Agent mode:** restart the server, then reload the VS Code window (`Ctrl+Shift+P` → `Developer: Reload Window`).

This starter configures the connection only. It cannot install VS Code extensions or authenticate on your behalf.