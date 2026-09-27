# Network Forensics Dashboard Upgrade

The Network Forensics viewport now uses endpoint-supplied telemetry only and is organized for Tier 2/3 triage:

- Alert status derived from observed administration-port traffic and measured packet-drop rate.
- Ingress/egress rates derived from endpoint interface byte counters across manual refresh samples.
- Packet-loss rate derived from endpoint packet/drop counter deltas across manual refresh samples.
- Traffic volume timeline from real interface counters observed during manual refreshes.
- Beaconing analysis only appears when the same destination is observed across at least three refresh samples; otherwise the UI states that periodicity cannot be established.
- Protocol counts from actual socket observations.
- DNS anomaly indicators are only computed when DNS query/cache telemetry is actually supplied.
- Exfiltration host volume is explicitly marked not assessed because socket snapshots do not provide per-destination byte accounting.
- Lateral movement candidates are based on observed internal connections to ports 445, 3389 and 5985.
- Granular flow table uses UTC timestamps and flags administration ports 445/3389/5985.
- Encrypted outbound connections are marked as reputation-not-assessed unless a reputation source is configured; the dashboard does not invent reputation results or threat intelligence.
- No demo/synthetic network records are added.

The agent network payload now includes interface byte/packet/drop counters and DNS observations when available.
