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
| [ROADMAP.md](ROADMAP.md) | Development roadmap and future phases | ✅ |
| [Architecture Diagram](diagrams/architecture.png) | System design and data flow | 🚧 |
| [Screenshots](screenshots/) | Dashboard and Graphify screenshots | 🚧 |
| [Journal](journal/) | Development notes and design decisions | 🚧 |
| [Security Considerations](SECURITY.md) | Detection assumptions, threat model and limitations | 🚧 |
| [Sample Logs](sample_logs/) | Test datasets used for parser validation | ✅ |
| [Outputs](outputs/) | Generated events, detections and alerts | 🚧 |

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

Current detections include:

### SSH Brute Force

Detection of:

- Fast brute force attempts
- Slow brute force attacks
- Root targeting attempts
- Repeated PAM authentication failures

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
│   └── bruteforce.py
│
├── sample_logs/
│   └── ssh_sample.txt
│
├── outputs/
│
├── tests/
│
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
- [ ] Service anomalies
- [ ] Root activity monitoring
- [ ] Persistence indicators
- [ ] Behaviour analysis

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

> Improving parser robustness, expanding detections, and preparing the event pipeline for additional log sources.

---

## Author

Ankit Bembalgi

Cybersecurity Enthusiast • AI Engineer • Automation Builder
