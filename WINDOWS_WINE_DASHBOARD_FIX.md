# Windows Generate & Download — Wine Prefix Fix

If the dashboard previously reported:

    wine: could not load kernel32.dll, status c0000135

the server was usually invoking Wine with a different/broken prefix than the
one used interactively.

The builder now:
- honors WINEPREFIX when explicitly set;
- otherwise prefers `~/.jocky-wine` when it exists;
- falls back to `~/.wine`;
- initializes the selected prefix with `wineboot -u`;
- uses the same prefix for Wine Python, pip and PyInstaller.

Recommended one-time setup:

    export WINEPREFIX="$HOME/.jocky-wine"
    export WINEARCH=win64
    wineboot -u

Then start the JOCKY server from that same shell, or let the builder discover
`~/.jocky-wine` automatically.
