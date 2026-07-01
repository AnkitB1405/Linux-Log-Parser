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

Current Progress: ~80%

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

## SSH Detection Engine

Implemented:

- [x] Fast Brute Force
- [x] Slow Brute Force
- [x] Root Login Monitoring
- [x] PAM Correlation
- [x] Unknown Root Login Detection

Planned:

- [ ] Service Restart Detection
- [ ] Credential Compromise Detection
- [ ] Session Anomaly Detection
- [ ] Behaviour Correlation
- [ ] Login Pattern Analysis

## Engineering

- [x] Error Handling
- [ ] Persist Events
- [ ] Persist Alerts
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

Current Progress: ~15%

Planned detectors:

- [ ] Service Anomaly Detector
- [ ] Credential Compromise Detector
- [ ] Persistence Detector
- [ ] Behaviour Detector
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

# Phase 4 — Event Normalization

Current Progress: ~20%

Current schema:

```python
{
    "event_type": "...",
    "source_ip": "...",
    "timestamp": ...
}
```

Target schema:

```python
{
    "id": "...",

    "source": "ssh",

    "event_type": "...",

    "timestamp": ...,

    "host": "...",

    "severity": "...",

    "user": "...",

    "source_ip": "..."
}
```

Goals:

- [ ] Unified Event Schema
- [ ] UUID support
- [ ] Event Source Tracking
- [ ] Host Tracking

---

# Phase 5 — Outputs

Current Progress: 0%

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

- [ ] Save parsed events
- [ ] Save alerts
- [ ] Save detections
- [ ] Historical retention

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

Phase 1   ████████░░ 80%

Phase 2   ░░░░░░░░░░ 0%

Phase 3   ██░░░░░░░░ 15%

Phase 4   ███░░░░░░░ 20%

Phase 5   ░░░░░░░░░░ 0%

Phase 6   ░░░░░░░░░░ 0%

Phase 7   ░░░░░░░░░░ 0%

Phase 8   ░░░░░░░░░░ 0%

Phase 9   ░░░░░░░░░░ 0%

Phase 10  ░░░░░░░░░░ 0%
```

---

**Project Status:** 🚧 Active Development

Current Focus:

> Completing SSH detections, improving event persistence, and preparing for additional log sources.