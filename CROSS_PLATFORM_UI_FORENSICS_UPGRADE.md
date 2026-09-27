# JOCKY DFIR Gateway — Cross-Platform UI & Endpoint Forensics Upgrade

This upgrade keeps the existing feature-rich project as the base and improves the Linux/Windows parity and investigator UI.

## Changes

- B1–B12 dashboard engine status is now a readable 12-card grid. B11 and B12 are explicitly shown.
- Case banner derives the target OS/hostname from the assigned endpoint telemetry instead of assuming Windows.
- Messaging B3 now falls back to the assigned endpoint's rich telemetry when normalized message rows are absent.
- Email B4 now uses the assigned endpoint's rich `EmailForensicsCollector` payload and displays detected mail clients when message rows are absent.
- Web & Social B5 is derived from the assigned endpoint browser history when normalized rows are absent.
- Device & Hardware B6 uses assigned endpoint rich telemetry when normalized rows are absent.
- B7 CPU, physical/logical cores, RAM and live memory usage are normalized across Linux and Windows.
- Process view prefers assigned endpoint rich process telemetry and exposes parent/child relationships and working directory.
- Filesystem opens at the actual endpoint root (`/` on Linux, `C:\` on Windows), supports Back/Up navigation, read-only preview/metadata, and archive member browsing.
- ZIP/TAR/GZ members can be opened for bounded read-only preview and metadata without extraction.
- Timeline and log timestamps are displayed as human-readable UTC values while raw payloads remain available.
- Log messages are presented in a readable form with a Details view containing the original payload.
- Plain-language explanations were added throughout forensic views for non-technical investigators.
- Removed dashboard fallbacks that could display previously seen Windows sample host values.

## Verification

- 111 Python source files compile successfully.
- All dashboard JavaScript script blocks pass Node syntax checking.
- Linux collector smoke checks run for B3, B4, B6, B7 and B8.
- No synthetic Windows host values were found in `server/`, `agent/`, or `collector/` after the upgrade.

## Important operational behavior

- The dashboard remains manual-refresh driven.
- Evidence remains read-only.
- The selected case is resolved to its assigned endpoint/device for telemetry and filesystem operations.
- `NO_EVIDENCE_FOUND`, `NOT_PRESENT`, and `NOT_ACCESSIBLE` remain distinct states; absence of evidence is not replaced with fabricated records.
