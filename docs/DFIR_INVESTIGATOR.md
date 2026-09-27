# JOCKY DFIR Investigator

The investigator correlates triage artifacts into a single chronological timeline and identifies suspicious patterns using host metadata only.

## Privacy boundary

The investigator accepts process trees, executable paths, command-line metadata, domains/IPs, timestamps, file paths and hashes. It does **not** decrypt or extract passwords, browser cookies, authentication/session tokens, message contents, or other credential material.

## Analysis rules

- Process execution from AppData/Temp/Public/Downloads is flagged for review.
- PowerShell encoded-command and download-oriented parameters are flagged.
- Supplied IOC domains/IPs are matched exactly against observed domains/IPs.
- USB connection events are correlated with nearby export/copy/deletion/archive activity.
- Browser downloads/Zone.Identifier events are correlated with nearby script-capable execution.
- Every input event is preserved as normalized timeline metadata; absence of an artifact is not converted into dummy data.

## API

`POST /api/forensics/investigate`

Example JSON body:

```json
{
  "data": [
    {"timestamp":"2026-09-24T07:00:00Z","event_type":"process_start","executable":"C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe","command_line":"x.exe"},
    {"timestamp":"2026-09-24T07:02:00Z","event_type":"network_connection","domain":"example.test","remote_port":443}
  ],
  "indicators": ["example.test"]
}
```

`POST /api/forensics/investigate/report` returns a Markdown investigation report containing:

1. Executive Summary (max 250 words)
2. Key Artifact Chronological Timeline
3. Detected Suspicious Findings & IOCs
4. Recommended Remediation & Containment Steps

## CLI

```bash
python tools/dfir_investigate.py artifacts.json --report-out investigation.md --json-out investigation.json
```
