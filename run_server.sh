#!/usr/bin/env bash
# JOCKY Combined — Start Central Server
# Binds to all interfaces and prints localhost + every detected LAN IPv4 address.
set -e

# Configuration is loaded by Python from .env when present. Copy .env.example to .env for local deployment.

VENV_DIR="${VENV_DIR:-venv}"
if [ -d "$VENV_DIR" ]; then
    source "$VENV_DIR/bin/activate" 2>/dev/null || true
fi

# Keep an explicitly supplied JOCKY_HOST, otherwise listen on all interfaces
# so authorized devices on the same network can reach the server.
export JOCKY_HOST="${JOCKY_HOST:-0.0.0.0}"
export JOCKY_PORT="${JOCKY_PORT:-5000}"

echo "[JOCKY] Starting central forensic server..."
echo "[JOCKY-SERVER] Bind: ${JOCKY_HOST}:${JOCKY_PORT}"
echo "[JOCKY-SERVER] Local: http://127.0.0.1:${JOCKY_PORT}"

# Print every non-loopback IPv4 address, not just the first one.
declare -a IPS=()

if command -v ip >/dev/null 2>&1; then
    while IFS= read -r ipaddr; do
        [ -n "$ipaddr" ] && IPS+=("$ipaddr")
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | awk '!seen[$0]++')
fi

# Fallback for systems where `ip` is unavailable.
if [ "${#IPS[@]}" -eq 0 ] && command -v hostname >/dev/null 2>&1; then
    while IFS= read -r ipaddr; do
        [ -n "$ipaddr" ] && IPS+=("$ipaddr")
    done < <(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $0 !~ /^127\./' | awk '!seen[$0]++')
fi

if [ "${#IPS[@]}" -eq 0 ]; then
    echo "[JOCKY-SERVER] LAN:    No non-loopback IPv4 address detected"
else
    for ipaddr in "${IPS[@]}"; do
        echo "[JOCKY-SERVER] LAN:    http://${ipaddr}:${JOCKY_PORT}"
    done
fi

python3 -m server.server
