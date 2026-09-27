# JOCKY V5 — Linux Forensics / Dashboard Fixes

This revision fixes the dashboard workflow so Linux endpoints use endpoint telemetry instead of Windows-only collectors and the active forensic views do not display synthetic values.

## 1. Physical Device Forensics

The active dashboard now focuses on:

- physical USB/removable devices actually observed by the endpoint
- connection/attach/detach timestamps when an artifact provides them
- files for which endpoint evidence records filesystem activity
- explicit transfer evidence only when the source artifact establishes a transfer
- evidence source and confidence for every event

Linux collection sources include `/sys/bus/usb/devices`, `lsblk`, `/proc/mounts`, the kernel journal, and Linux auditd when available.

A file access is **not** automatically classified as a file transfer. Linux does not provide a universal historical copy log. The dashboard therefore reports `UNDETERMINED` instead of inventing a direction.

The live agent also detects physical-device attach/detach changes and sends them through the existing live-event channel.

## 2. File Browser & Hex

Linux browsing now returns Autopsy-style live metadata including:

- inode, UID/GID, owner/group and link count
- permissions/mode
- modification, access and filesystem-change timestamps
- Linux birth time when the filesystem exposes it
- SHA-256 for readable regular files
- magic/header bytes and extension mismatch detection
- read-only content preview
- bounded raw hex view

The filesystem root is selected automatically from the enrolled endpoint OS (`/` for Linux and `C:\` for Windows).

Deleted-file scanning on Linux no longer treats temporary files as deleted evidence. For ext2/ext3/ext4, JOCKY uses `findmnt` and `debugfs lsdel` to enumerate deleted inodes when the required tooling and permissions are available. A deleted inode can be read through `debugfs cat` without creating a synthetic replacement file.

Deleted-file recovery is explicitly marked as candidate/recoverable and may fail when inode blocks have been reused.

## 3. Email Forensics

The email intelligence endpoint is now agent-aware. For an enrolled Linux endpoint, the server consumes the agent's real email artifact telemetry rather than scanning the server host as a substitute.

The active UI is evidence-first:

- message count
- attachment count
- participants
- recovered messages
- sender/recipient/subject/date/source search

No placeholder messages are inserted when the endpoint has no mail evidence.

## 4. Location Intelligence

Linux location collection now checks:

- NetworkManager Wi-Fi telemetry when `nmcli` is available
- current Wi-Fi via `iwgetid` as a fallback
- NetworkManager journal connection events
- NetworkManager connection profiles
- Linux browser location preference locations
- EXIF GPS artifacts
- public-IP geolocation when network access is available

The UI no longer hardcodes a city, coordinates, GPS count, or device list. Coordinates are displayed only when a real artifact supplies them.

The timestamp search can query the endpoint's stored location telemetry history.

## 5. Network Forensics

Linux network intelligence now uses:

- `ss` / `netstat` for active sockets
- psutil for network interfaces
- NetworkManager for configured Wi-Fi connections
- NetworkManager journal entries for connection events
- resolver configuration for DNS-server evidence

The active dashboard no longer presents a Demo Mode control. The backend demo dataset remains isolated for explicit UI testing and is not used by the normal Linux/Windows dashboard workflow.

## Evidence integrity rule

The normal dashboard path does not manufacture filenames, timestamps, hashes, locations, connection sessions, email messages, or deleted files. If an artifact is unavailable, the UI shows an empty/unknown state and identifies the missing evidence source.

## Operational requirements on Linux

For richer evidence, run the authorized agent with the required privileges for the artifacts under investigation. Depending on the endpoint, useful packages/services include:

- `systemd` / `journalctl`
- `util-linux` (`lsblk`, `findmnt`, `stat`)
- `e2fsprogs` (`debugfs`) for ext filesystem deleted-inode analysis
- NetworkManager (`nmcli`) for Wi-Fi telemetry
- `auditd` / `ausearch` for historical filesystem access auditing
- `psutil` Python package

Absence of one of these tools does not create fallback fake evidence; the corresponding evidence category remains unavailable.

## 2026-09-16 integration repair

- Restored endpoint-artifact flow for Email Intelligence; the server now analyzes the enrolled agent's email artifacts instead of rescanning the central host.
- Restored endpoint-artifact flow for Location Intelligence, including timestamped GPS/EXIF, browser, Wi-Fi/NetworkManager, and IP evidence where actually recovered.
- Fixed Firefox Linux profile handling so `~/.mozilla/firefox` is treated as a profile directory rather than parsed as a JSON file.
- Normal filesystem browsing no longer performs deleted-file recovery on every directory request; deleted-file recovery is explicit from the Deleted Files view.
- Physical-device activity searches now consume enrolled-agent removable-media evidence.
- Linux Network Forensics now merges active connections, interface telemetry, Wi-Fi observations and endpoint log evidence rather than falling back to the central server's Windows-oriented collector.
- Removed a fabricated Linux network-interface fallback (`eth0`, `127.0.0.1`, `8.8.8.8`). Empty evidence remains empty.
- Dashboard location overview no longer uses hardcoded Bengaluru/sample counts when real evidence is absent.
