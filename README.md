# Homelab Log Parser (Linux) 

An ongoing cybersecurity project focused on building a lightweight log analysis and detection engine for Linux systems.

The project aims to normalize logs from multiple sources, detect suspicious behaviour through rule-based analysis, and provide visual insights through dashboards and Graphify integration.

---

## Objectives

This project is intended to evolve into a small-scale SIEM-like platform capable of:

- Parsing Linux log sources
- Normalizing events into a common schema
- Detecting malicious or anomalous behaviour
- Generating alerts
- Providing visual analytics
- Supporting AI-assisted incident analysis (future work)

---

## Documentation

The following documents and artifacts are maintained as part of the project engineering process.

| Resource | Purpose | Status |
|----------|---------|--------|
| [DOCUMENTATION.md](DOCUMENTATION.md) | Development Journal | ✅ |
| [ROADMAP.md](ROADMAP.md) | Project Roadmap | ✅ |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System Design | 🚧 |
| [SECURITY.md](SECURITY.md) | Threat Model | 🚧 |
| [screenshots/](screenshots/) | Visual Assets | 🚧 |
| [journal/](journal/) | Notes | 🚧 |
| [outputs/](outputs/) | Events and Alerts | ✅ |
| [test_detectors.py](test_detectors.py) | Detection Regression Test | ✅ |

---

## Current Features

### SSH Parser

Supported SSH events:

- Successful login
- Failed login
- Invalid user
- Authentication failures
- Multiple authentication failures
- Session opened
- Connection closed
- SSH service started
- SSH service stopped

Every parser routes through a single normalized schema
(`parser/event_schema.py`), so all log sources — current and future — emit the
same shape:

```python
{
    "id": "b1c2a0054d24",          # short uuid4 — lets alerts reference evidence
    "timestamp": datetime(...),    # taken from the log line, not wall clock
    "log_source": "ssh",
    "host": "Sentinel",
    "event_type": "failed_login",
    "severity": None,              # set by detectors, not by parsers
    "username": "guest",
    "source_ip": "198.51.100.10",
    "details": {}                  # source-specific extras (PAM uid/tty, ...)
}
```

---

## Detection Engine

The SSH detection engine now runs five independent detectors over the normalized event stream.

### Current Detections

| Detector | Detects |
|----------|---------|
| **Brute Force** | Fast/slow brute force, root targeting, PAM correlation, unknown root logins |
| **Service Anomaly** | Repeated SSH service restarts / instability |
| **Credential Compromise** | Failed-login bursts followed by a success on the same user + IP |
| **Behaviour Analysis** | Distributed / patterned attacker behaviour across sliding windows |
| **Session Anomaly** | Abnormally short SSH sessions |

### SSH Brute Force

Detection of:

- Fast brute force attempts
- Slow brute force attacks
- Root targeting attempts
- Repeated PAM authentication failures
- Unknown root login detection

### Service Anomaly

Detects repeated SSH service start/stop cycles within a short window (service instability).

### Credential Compromise

Correlates a burst of failed logins followed by a successful login on the same user and source IP.

### Behaviour Analysis

Tracks per-IP failed-login activity across sliding time windows to surface distributed or patterned attacker behaviour.

### Session Anomaly

Flags sessions that open and close within seconds.

Severity levels:

- Monitor
- Medium
- High

Examples:

```text
Single PAM signal
→ Medium

Multiple PAM signals within 3 minutes
→ High

Root login attempts
→ Elevated priority

Repeated failed logins over 10 minutes
→ Slow brute force detection

Failed-login burst then success (same user + IP)
→ Credential compromise

Repeated SSH service restarts
→ Service instability
```

### Alert Format

Every alert is anchored in time and in evidence — it records **when** the
condition became true, and the ids of the exact events that raised it:

```python
{
    "severity": "medium",
    "alert_type": "credential_compromise",
    "service": "ssh",
    "username": "analyst",
    "source_ip": "192.0.2.20",
    "failed_attempts": 5,
    "timestamp": datetime(...),                    # from the log, not the clock
    "event_ids": ["7f3a...", "9c11...", ...],      # resolvable against events.json
    "recommended_action": "verify login"
}
```

This makes an alert auditable: `event_ids` resolve against
`outputs/events.json` to reconstruct the raw lines behind any detection.

---

## Testing

```bash
python3 test_detectors.py
```

A dependency-free regression check (plain `assert`, no framework). It pins the
alert set produced by `sample_logs/ssh_dataset_v1.txt` — verified by hand as
11/11 attack scenarios detected with 0 false positives — along with the event
mix, the normalized event shape, event id uniqueness, and the invariant that
no alert may predate its own evidence. Any threshold, window or parser change
that moves the result set fails this test, so behaviour changes have to be
deliberate.

---

## Project Structure

```text
Log_Parser/

├── main.py
├── parser/
│   ├── ssh_parser.py
│   └── event_schema.py
│
├── detectors/
│   ├── bruteforce.py
│   ├── service_anomaly.py
│   ├── credential_compromise.py
│   ├── behavior.py
│   └── session_anomaly.py
│
├── sample_logs/
│   ├── sample_ssh_log.txt
│   └── ssh_dataset_v1.txt
│
├── graphify-out/
│
├── outputs/
│   ├── persistence.py
│   ├── stats.py
│   ├── events.json
│   ├── alerts.json
│   └── statistics.json
│
├── test_detectors.py
│
├── DOCUMENTATION.md
├── ARCHITECTURE.md
├── SECURITY.md
├── ROADMAP.md
├── Convos_and_notes.txt
│
└── README.md
```

---

## Workflow

```text
Raw Logs

↓

Parsers

↓

Normalized Events

↓

Detection Engine

↓

Alerts

↓

Dashboard / Graphify

↓

Analyst Review
```

---

# Graphify Support

Graphify is planned as the primary visualization component for this project.

Potential visualizations include:

- Failed login trends
- Alert timelines
- Top attacker IPs
- Service activity
- Detection statistics
- Event distributions
- Historical behaviour analysis

Graphify integration is currently under development.

---

# Roadmap

## V1

Focus on foundational log parsing and detections.

### Parsers

- [x] SSH
- [ ] Docker
- [ ] Syslog
- [ ] Authentication Logs
- [ ] Apache/Nginx

### Detectors

- [x] Brute force
- [x] Service anomaly
- [x] Credential compromise
- [x] Behaviour analysis
- [x] Session anomaly
- [x] Root activity monitoring
- [ ] Persistence indicators

### Alerting

- [ ] Local alerts
- [ ] Dashboard alerts
- [ ] Export functionality

---

## V2

Advanced analytics and AI-assisted investigation.

Planned capabilities:

- Event correlation
- Baseline behaviour modelling
- Docker monitoring
- Container anomaly detection
- AI-powered incident summaries
- Recommendations engine
- External integrations
- Real-time monitoring
- Alert forwarding
- Incident timelines

---

## Design Philosophy

This project is being developed primarily as a learning-oriented cybersecurity engineering exercise.

Goals:

- Understand Linux internals
- Learn detection engineering
- Build practical parser pipelines
- Explore SIEM concepts
- Experiment with event correlation
- Develop security analytics workflows

---

## Status

🚧 Ongoing Project

Actively being developed and expanded.

Current focus:

> Event schema unification is complete — all parsers emit one normalized shape and every alert links back to the log lines that raised it. Next: refining the detector severity bands, then adding the second (non-SSH) parser.

---

## Author

Ankit Bembalgi

Cybersecurity Enthusiast • AI Engineer • Automation Builder
