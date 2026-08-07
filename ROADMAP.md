# Linux Log Parser - Development Roadmap

Current Status: 🚧 Ongoing Project

---

# Phase 0 — Architecture & Planning ✅

Completed foundational planning and design.

### Completed

- [x] Repository structure
- [x] Parser architecture
- [x] Event normalization discussion
- [x] Detector architecture
- [x] Sample datasets
- [x] Timestamp implementation
- [x] V1 and V2 scope definition
- [x] Correlation planning

---

# Phase 1 — SSH Monitoring Engine 🔄

Current Progress: ~95%

## SSH Parser

- [x] Successful Login
- [x] Failed Login
- [x] Invalid User
- [x] Authentication Failure
- [x] Multiple Authentication Failures
- [x] Session Opened
- [x] Connection Closed
- [x] Service Started
- [x] Service Stopped
- [x] Timestamp support
- [x] Parser robustness improvements
- [x] All parsers routed through the normalized schema
- [ ] Accepted publickey (key-based logins currently produce no event)
- [ ] Year-aware timestamps (syslog carries no year — see `ssh_parser.py:15`)

## SSH Detection Engine

Implemented:

- [x] Fast Brute Force
- [x] Slow Brute Force
- [x] Root Login Monitoring
- [x] PAM Correlation
- [x] Unknown Root Login Detection
- [x] Service Restart Detection
- [x] Credential Compromise Detection
- [x] Session Anomaly Detection
- [x] Behaviour Correlation

Planned:

- [ ] Login Pattern Analysis

## Engineering

- [x] Error Handling
- [x] Persist Events
- [x] Persist Alerts
- [x] Alert → event traceability (`event_ids`)
- [x] Regression test for the detection engine (`test_detectors.py`)
- [ ] Severity band fixes (`credential_compromise` high branch unreachable; duplicate `behavior_anomaly`)
- [ ] Detection History
- [ ] Event Archiving

---

# Phase 2 — Additional Parsers

Current Progress: 0%

## Docker Parser

Planned events:

- [ ] Container Started
- [ ] Container Stopped
- [ ] Container Restarted
- [ ] Container Created
- [ ] Container Deleted
- [ ] Container Exec

---

## Syslog Parser

Planned events:

- [ ] Service Events
- [ ] Kernel Events
- [ ] Cron Events
- [ ] Networking Events
- [ ] System Events

---

## Authentication Parser

Planned events:

- [ ] sudo
- [ ] passwd
- [ ] useradd
- [ ] userdel
- [ ] usermod
- [ ] su

---

## Apache / Nginx Parser

Planned events:

- [ ] 404 Detection
- [ ] 500 Error Detection
- [ ] Web Scanning Detection
- [ ] Traffic Anomalies

---

# Phase 3 — Detection Expansion

Current Progress: ~35%

Implemented detectors:

- [x] Service Anomaly Detector
- [x] Credential Compromise Detector
- [x] Behaviour Detector

Planned detectors:

- [ ] Persistence Detector
- [ ] Container Anomaly Detector
- [ ] Lateral Movement Detector
- [ ] Network Abuse Detector

Examples:

### Service Instability

Repeated SSH restarts.

### Persistence Detection

useradd

↓

SSH key added

↓

cron modification

↓

Alert

### Behaviour Analysis

Distributed login attempts

↓

Slow brute force detection

---

# Phase 4 — Event Normalization ✅

Current Progress: 100%

Every parser now returns `parser/event_schema.py:create_event()`. There is
one event shape in the system, and the detectors, statistics and persistence
layers all consume it.

Implemented schema:

```python
{
    "id": "b1c2a0054d24",          # short uuid4 — links alerts back to evidence

    "timestamp": datetime(...),    # from the log line, not wall clock

    "log_source": "ssh",

    "host": "Sentinel",

    "event_type": "failed_login",

    "severity": None,              # set by detectors, not by parsers

    "username": "guest",

    "source_ip": "198.51.100.10",

    "details": {}                  # per-source extras (PAM uid/tty, session initiated_by, ...)
}
```

Goals:

- [x] Unified Event Schema
- [x] UUID support
- [x] Event Source Tracking
- [x] Host Tracking
- [x] Alerts carry a timestamp and the `event_ids` that justify them

Naming note: the original plan called these fields `source` and `user`. The
shipped names are `log_source` and `username`, matching what the detectors and
alert dicts already used — renaming six files to match a planning document was
not worth it. `details` was added so a new parser can carry source-specific
fields without widening the common shape for everyone else.

---

# Phase 5 — Outputs 🔄

Current Progress: ~50%

Current structure:

```text
outputs/
├── persistence.py     # save_events / save_alerts / save_statistics
├── stats.py           # generate_statistics
├── events.json        # regenerated every run
├── alerts.json        # regenerated every run
└── statistics.json    # regenerated every run
```

Planned structure:

```text
outputs/

events.json

alerts.json

detections.json

statistics.json

history/

daily/

weekly/
```

Planned capabilities:

- [x] Save parsed events
- [x] Save alerts
- [x] Run statistics
- [ ] Historical retention
- [ ] `monitor`-severity alerts get their own statistics bucket

Outputs are overwritten on every run — there is no run history and no alert
deduplication yet.

---

# Phase 6 — Graphify Integration

Current Progress: 0%

Graphify will be used for visualization.

Planned views:

- [ ] Event Timeline
- [ ] Alert Timeline
- [ ] Failed Login Trends
- [ ] Top Source IPs
- [ ] Root Activity
- [ ] Service Activity
- [ ] Detection Statistics
- [ ] Attack Heatmaps

---

# Phase 7 — Dashboard

Current Progress: 0%

Potential frameworks:

- Streamlit
- Graphify
- Flask
- React

Dashboard sections:

- [ ] Overview
- [ ] Events
- [ ] Alerts
- [ ] Detections
- [ ] Sources
- [ ] Statistics

---

# Phase 8 — Alerting

Current Progress: 0%

Integrations:

- [ ] Discord
- [ ] Telegram
- [ ] Slack
- [ ] Email
- [ ] Webhooks

---

# Phase 9 — Real-Time Monitoring

Current Progress: 0%

Current state:

```text
Sample Logs

↓

Parser

↓

Detector
```

Target:

```text
journalctl -f

↓

Parser

↓

Detectors

↓

Alerts

↓

Dashboard
```

Planned capabilities:

- [ ] Live Monitoring
- [ ] Streaming Events
- [ ] Continuous Detection
- [ ] Sliding window state management
- [ ] Event expiry
- [ ] Detector memory cleanup
- [ ] Stateful detection optimization

---

# Phase 10 — AI Layer (V2)

Current Progress: 0%

Planned functionality:

- [ ] Alert Summarization
- [ ] Incident Reports
- [ ] Behaviour Analysis
- [ ] Threat Classification
- [ ] Suggested Mitigations
- [ ] Attack Pattern Analysis

Example:

```text
Bruteforce Attempt Detected

Target:
root

Source:
103.44.22.78

Observed:
4 failed logins

Risk:
High

Recommendation:
Block IP
Enable SSH Keys
Review Access Logs
```

---

# V1 Goals

Homelab Monitoring Platform

Focus Areas:

- SSH Monitoring
- Docker Monitoring
- Syslog Monitoring
- Detection Rules
- Visualization
- Alerting

---

# V2 Goals

Detection Engineering Platform

Focus Areas:

- Correlation
- Behaviour Analysis
- AI Assistance
- Real-Time Monitoring
- Incident Investigation
- Threat Intelligence
- Automated Response

---

# Progress Overview

```text
Phase 0   ██████████ 100%

Phase 1   █████████░ 95%

Phase 2   ░░░░░░░░░░ 0%

Phase 3   ████░░░░░░ 35%

Phase 4   ██████████ 100%

Phase 5   █████░░░░░ 50%

Phase 6   ░░░░░░░░░░ 0%

Phase 7   ░░░░░░░░░░ 0%

Phase 8   ░░░░░░░░░░ 0%

Phase 9   ░░░░░░░░░░ 0%

Phase 10  ░░░░░░░░░░ 0%
```

---

**Project Status:** 🚧 Active Development

Current Focus:

> Phase 4 is closed — the schema is unified and alerts are traceable back to
> the log lines that raised them. Next: the severity band fixes, then the
> second (non-SSH) parser, which the normalized schema now makes cheap.