#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If the operator already exported WINEPREFIX, keep it.
# Otherwise prefer the dedicated JOCKY Wine prefix when it exists.
if [[ -z "${WINEPREFIX:-}" ]]; then
  if [[ -d "$HOME/.jocky-wine/drive_c" ]]; then
    export WINEPREFIX="$HOME/.jocky-wine"
  elif [[ -d "$HOME/.wine/drive_c" ]]; then
    export WINEPREFIX="$HOME/.wine"
  else
    export WINEPREFIX="$HOME/.jocky-wine"
  fi
fi

export WINEARCH="${WINEARCH:-win64}"
echo "[JOCKY-WINE] WINEPREFIX=$WINEPREFIX"
echo "[JOCKY-WINE] WINEARCH=$WINEARCH"

exec python3 "$SCRIPT_DIR/build_wine_windows.py" "$@"
