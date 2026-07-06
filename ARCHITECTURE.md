# Architecture — Homelab Log Parser (Linux)

System design and data flow for the log parsing and detection engine.

Status: 🚧 Evolving. This document describes both the **current** implemented architecture and the **planned** target architecture.

---

## Parser Pipeline

```text
Logs
 ↓
Parsers
 ↓
Normalized Events
 ↓
Detectors
 ↓
Alerts
 ↓
Outputs
 ↓
Dashboard
 ↓
Graphify
```

Stages currently implemented end-to-end: **Logs → Parsers → Normalized Events → Detectors → Alerts** (alerts printed to stdout).
Stages not yet implemented: **Outputs (persistence), Dashboard, Graphify integration** (Graphify scaffolding exists but is not wired to live alerts).

---

## Current Architecture

```text
sample_logs/ssh_dataset_v1.txt
        │
        ▼
parser/ssh_parser.py
  identify_event(line) ──► parse_* functions ──► normalized event dict
        │
        ▼
   events[]  (+ errors[] for unparseable lines)
        │
        ├──► detectors/bruteforce.py            ──► alerts
        ├──► detectors/service_anomaly.py       ──► alerts
        ├──► detectors/credential_compromise.py ──► alerts
        ├──► detectors/behavior.py              ──► alerts
        └──► detectors/session_anomaly.py       ──► alerts
                                                     │
                                                     ▼
                                              stdout (main.py)
```

**Components:**

| Layer | Module(s) | Responsibility |
|-------|-----------|----------------|
| Entry | `main.py` | Read log file, drive parser, run all detectors, print alerts + errors |
| Parser | `parser/ssh_parser.py` | Identify SSH event type and normalize into an event dict |
| Schema | `parser/event_schema.py` | `create_event(...)` helper for a normalized event shape |
| Detection | `detectors/*.py` | Consume the event list, emit alert dicts |
| Data | `sample_logs/*.txt` | Synthetic log datasets for validation |
| Visualization | `graphify-out/` | Generated code/knowledge graph (not yet fed by alerts) |

**Control flow:** batch — one file is read fully into memory, all events are collected, then each detector runs over the complete list. There is no streaming and no persisted state between runs.

---

## Planned Architecture

```text
journalctl -f / log files
        │
        ▼
   Parser Registry  (ssh, syslog, auth, docker, apache/nginx)
        │
        ▼
   Normalized Event Bus  (unified schema + UUID + source + host)
        │
        ▼
   Detector Engine  (stateful, sliding-window, expiring memory)
        │
        ▼
   Alert Store  ──► outputs/{events,alerts,detections,statistics}.json
        │
        ▼
   Dashboard (Streamlit/Flask)  +  Graphify visualizations
        │
        ▼
   Alerting (Discord / Telegram / Slack / Email / Webhooks)
        │
        ▼
   AI Layer (V2): summaries, incident reports, mitigations
```

---

## Event Schema

**Current** — parsers return event dicts. The SSH parser emits (representative):

```python
{
    "event_type": "failed_login",     # required
    "service": "ssh",                 # source/service
    "username": "root",               # event-specific
    "source_ip": "185.12.41.55",      # event-specific
    "timestamp": datetime(...)        # required, parsed at parse time
}
```

A normalization helper exists in `parser/event_schema.py`:

```python
create_event(timestamp, log_source, event_type, severity, host, details)
# → {timestamp, log_source, event_type, severity, host, details}
```

> Note: parsers currently emit their own dict shape directly rather than routing through `create_event`. Unifying the two is a Phase 4 goal.

**Target (unified) schema:**

```python
{
    "id":         "<uuid>",
    "source":     "ssh",
    "event_type": "failed_login",
    "timestamp":  datetime(...),
    "host":       "<hostname>",
    "severity":   "medium",
    "user":       "root",
    "source_ip":  "185.12.41.55",
    "details":    { ... }
}
```

---

## Alert Schema

Detectors emit alert dicts. Common fields observed across detectors:

```python
{
    "severity":           "monitor | medium | high",
    "alert_type":         "bruteforce | slow_bruteforce | root_attack |
                           root_bruteforce | unknown_root_login |
                           service_instability | credential_compromise |
                           behavior_anomaly | short_session",
    "source_ip":          "...",        # where applicable
    "username":           "...",        # where applicable
    "service":            "ssh",        # where applicable
    "recommended_action": "monitor | block_ip and report | investigate immediately | ..."
}
```

Additional context fields appear per detector (`attempts`, `failed_attempts`, `events`, `windows`, `duration`).

**Target:** alerts gain a stable `id`, an `event_ids` list linking back to contributing events, and a `timestamp` for the alert itself.

---

## Detector Philosophy

- **One detector per concern.** Each detector is a pure-ish function `detect_x(events) -> [alerts]`. They do not call each other.
- **Shared normalized event list.** Detectors read the same `events[]`; adding a detector is additive.
- **Time-window correlation.** Detection is based on `datetime`/`timedelta` windows (e.g. PAM ≤180s, slow brute force ≤600s, service ≤300s, behaviour ≤1800s, credential ≤600s, session ≤20s) rather than raw counts.
- **Severity tiers.** `monitor` → `medium` → `high`, each with a `recommended_action`.
- **Allowlists to cut noise.** e.g. `KNOWN_ROOT_IPS` suppresses expected root access.

---

## State Management Discussion

**Today:** detectors are *stateless across runs*. Each invocation rebuilds per-key dictionaries (per-IP, per-user, per-service) from the full event list and discards them when the function returns. This is simple and correct for batch processing of a bounded file, but:

- Memory grows with the size of the input file (everything is held at once).
- There is no notion of "events seen in previous runs."
- Re-running re-alerts on the same data.

**Target:** a stateful detector engine that maintains rolling per-entity windows in memory, so continuous input can be processed without holding the entire history.

---

## Future: Event Expiration

For streaming/continuous operation, detector memory must be bounded:

- **Sliding windows** — keep only events within the largest detection window per entity.
- **Event expiry** — drop timestamps older than the window on each tick.
- **Detector memory cleanup** — evict entities (IPs/users) with no recent activity.
- **Stateful detection optimization** — incremental updates instead of full recomputation.

This is tracked as Phase 9 (Real-Time Monitoring).

---

## Future: Streaming Design

```text
journalctl -f
     │  (line stream)
     ▼
  Parser  ──► normalized event
     │
     ▼
  Ring buffer / windowed state per entity
     │
     ▼
  Detectors run incrementally on each new event
     │
     ▼
  Alerts pushed to outputs/ + alerting channels + dashboard
```

Design goals: constant-memory operation, low latency from log line to alert, and back-pressure-free ingestion. Detectors become stateful consumers that update windows and emit alerts on threshold crossings rather than re-scanning a list.

---

*Kept in sync with `DOCUMENTATION.md` and `ROADMAP.md` as the architecture evolves.*
