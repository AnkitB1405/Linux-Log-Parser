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
| [outputs/](outputs/) | Events and Alerts | 🚧 |

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

Example normalized event:

```python
{
    "event_type": "failed_login",
    "username": "root",
    "source_ip": "185.12.41.55",
    "timestamp": datetime(...)
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

> Refining detector thresholds, adding event and alert persistence to `outputs/`, and preparing the normalized event schema for additional (non-SSH) log sources.

---

## Author

Ankit Bembalgi

Cybersecurity Enthusiast • AI Engineer • Automation Builder
