# Linux Log Parser Development Journal

A running engineering journal for the **Homelab Log Parser (Linux)** project.
Progress is reconstructed from actual repository history (`git log`, `git diff`, `README.md`, `ROADMAP.md`) — not inferred from code alone.

Repository: [AnkitB1405/Linux-Log-Parser](https://github.com/AnkitB1405/Linux-Log-Parser)

> **Boundary definition**
> **Day 1** = everything up to and including the state represented in the README snapshot (`27488fc`).
> **Day 2** = everything implemented after the README snapshot up to current `HEAD` (`4b91667`).

---

## Day 1

**Dates:** 2026-06-16 → 2026-07-02
**Commits:** 17 (`0ed0f45` … `27488fc`)

### Summary

Day 1 established the entire foundation of the project: the repository skeleton, the SSH log parser, the first detection engine (brute force family), timestamp-aware events, basic error handling, and the initial documentation set (README + roadmap). By the end of Day 1 the pipeline could take raw SSH logs, normalize them into structured events, and emit brute-force alerts.

### Implemented features

- **SSH parser** covering 9 event types:
  - Successful login
  - Failed login
  - Invalid user
  - Authentication failure (PAM / `pam_unix`)
  - Multiple authentication failures
  - Session opened
  - Connection closed
  - Service started
  - Service stopped
- **Timestamp parsing** (`parse_timestamp`) applied to every event, enabling time-window logic.
- **Brute-force detection engine** (`detectors/bruteforce.py`):
  - Fast brute force
  - Slow brute force (10-minute window)
  - Root login monitoring
  - PAM correlation (single vs. multiple signals within 3 minutes)
  - Unknown root login detection (against a known-good root IP allowlist)
- **Error handling** in the main loop — unparseable lines are captured into an `errors` list instead of crashing the run.
- **Graphify** scaffolding for future visualization.
- **Documentation baseline**: `README.md` and `ROADMAP.md`.

### Architecture decisions

- **Normalized event dictionaries** as the interface between parsers and detectors — each parser returns a dict with `event_type`, `timestamp`, and event-specific fields.
- **Detectors consume lists of events**, not raw log lines, keeping detection logic decoupled from parsing.
- **Time-window correlation** built on `datetime`/`timedelta` rather than naive counts.
- **Allowlist approach** for root logins (`KNOWN_ROOT_IPS`) to reduce noise from legitimate homelab access.

### Lessons learned

- SSH log lines vary in structure (`user X` vs. `for X`), so token-based parsing needs conditional handling.
- Timestamps must be attached at parse time — retrofitting them into detectors later is painful.
- Capturing parse errors as data (rather than exceptions) makes iterating on new log formats far easier.

### Commits table

| Commit | Description |
|--------|-------------|
| [3ca8cc5](https://github.com/AnkitB1405/Linux-Log-Parser/commit/3ca8cc5) | Added custom functions for each SSH log type with date/time in event output |
| [4e6b10e](https://github.com/AnkitB1405/Linux-Log-Parser/commit/4e6b10e) | Added more event types to the SSH parser |
| [c75344c](https://github.com/AnkitB1405/Linux-Log-Parser/commit/c75344c) | Fine-tuned auth failure event parsing |
| [9c5b84d](https://github.com/AnkitB1405/Linux-Log-Parser/commit/9c5b84d) | Removed sample SSH log from repo tracking |
| [77d7a48](https://github.com/AnkitB1405/Linux-Log-Parser/commit/77d7a48) | Added graphify |
| [66ace5e](https://github.com/AnkitB1405/Linux-Log-Parser/commit/66ace5e) | Added brute-force detector; added timestamp field to all SSH events |
| [598afe5](https://github.com/AnkitB1405/Linux-Log-Parser/commit/598afe5) | Added timedelta logic to detectors; added error section in response |
| [5500f19](https://github.com/AnkitB1405/Linux-Log-Parser/commit/5500f19) | Modified gitignore |
| [e1d74a2](https://github.com/AnkitB1405/Linux-Log-Parser/commit/e1d74a2) | Removed `detectors/__pycache__` from tracking |
| [bf685dd](https://github.com/AnkitB1405/Linux-Log-Parser/commit/bf685dd) | Graphify updated |
| [9c8ed08](https://github.com/AnkitB1405/Linux-Log-Parser/commit/9c8ed08) | Initialize README with project overview and details |
| [9cfd4bc](https://github.com/AnkitB1405/Linux-Log-Parser/commit/9cfd4bc) | Graphify updated |
| [b2dfeba](https://github.com/AnkitB1405/Linux-Log-Parser/commit/b2dfeba) | roadmap.md uploaded |
| [e84960c](https://github.com/AnkitB1405/Linux-Log-Parser/commit/e84960c) | Removed unnecessary file from repo |
| [43d91b6](https://github.com/AnkitB1405/Linux-Log-Parser/commit/43d91b6) | Same as before (cleanup) |
| [27488fc](https://github.com/AnkitB1405/Linux-Log-Parser/commit/27488fc) | **Update README to include project documentation (Day 1 snapshot)** |
| [0ed0f45](https://github.com/AnkitB1405/Linux-Log-Parser/commit/0ed0f45) | init |

### Metrics

| Metric | Value |
|--------|-------|
| Commits | 17 |
| Parsers | 1 (SSH) |
| SSH event types | 9 |
| Detectors | 1 (brute-force family) |
| Detection rules | 5 (fast BF, slow BF, root monitor, PAM, unknown root) |
| Sample datasets | 1 |

### Parser progress

SSH parser complete for all core auth/session/service events with timestamps. Robustness handling for `user`/`for` variants and invalid-user connection-close lines.

### Detection progress

Brute-force detection family fully implemented. No behavioral, credential, service, or session detectors yet.

### Engineering progress

Error capture in place. No persistence, no output files, no tests. Graphify scaffolded but not integrated.

---

## Day 2

**Dates:** 2026-07-02 → 2026-07-06
**Commits:** 4 (`0f76e99`, `de40543`, `ae4b7a8`, `4b91667`)

### Summary

Day 2 expanded the detection engine from one detector family to five. Four new anomaly detectors were added (service anomaly, credential compromise, behaviour correlation, session anomaly), the main pipeline was rewired to run all detectors, a larger synthetic dataset was introduced for validation, and the parser received robustness fixes. Graphify output was regenerated to reflect the new module graph.

### Implemented features

- **Service anomaly detector** (`detectors/service_anomaly.py`) — flags service instability from repeated `service_started`/`service_stopped` events within a 5-minute window (≥3 medium, ≥5 high).
- **Credential compromise detector** (`detectors/credential_compromise.py`) — correlates a burst of failed logins followed by a success on the same `(user, ip)` within 10 minutes.
- **Behaviour detector** (`detectors/behavior.py`) — sliding 30-minute windows per source IP; counts suspicious windows to distinguish steady/distributed attackers.
- **Session anomaly detector** (`detectors/session_anomaly.py`) — flags abnormally short sessions (open → close within 20 seconds).
- **Pipeline integration** — `main.py` now runs all five detectors and prints their alerts.
- **Synthetic dataset** — `sample_logs/ssh_dataset_v1.txt` added as the primary validation input.
- **Parser robustness fixes** — refinements to `ssh_parser.py` token handling.
- **Graphify regeneration** — `graphify-out/` updated for the expanded codebase.

### Architecture decisions

- **One detector per concern** — each detector is an independent function over the shared event list, so detectors compose without coupling.
- **Detector state stays local** — each detector rebuilds its own per-key dictionaries (per-IP, per-user, per-service) each run; no shared global state yet.
- **`event.get("service")` in alerts** — alerts carry the originating service to prepare for multi-source (non-SSH) parsers later.
- **Synthetic datasets as fixtures** — `ssh_dataset_v1` gives repeatable, labelled-ish input for exercising every detector.

### Lessons learned

- Independent detectors over a shared normalized event list scale cleanly — adding a detector is additive, not invasive.
- Threshold ordering matters: in a couple of detectors the `>=` bands are ordered such that the higher band can be shadowed by the lower one (a refinement target for a future day).
- A single realistic dataset that triggers every detector is worth more than many tiny fixtures.
- Regenerating the Graphify graph after structural changes keeps the visual model honest.

### Commits table

| Commit | Description |
|--------|-------------|
| [0f76e99](https://github.com/AnkitB1405/Linux-Log-Parser/commit/0f76e99) | Added all anomaly detectors (service, credential, behaviour, session); wired into main |
| [de40543](https://github.com/AnkitB1405/Linux-Log-Parser/commit/de40543) | New sample log set (`ssh_dataset_v1.txt`) |
| [ae4b7a8](https://github.com/AnkitB1405/Linux-Log-Parser/commit/ae4b7a8) | Updated parser a little (robustness fix) |
| [4b91667](https://github.com/AnkitB1405/Linux-Log-Parser/commit/4b91667) | Graphify regenerated for expanded codebase |

### Metrics

| Metric | Day 1 | Day 2 | Δ |
|--------|-------|-------|---|
| Commits (cumulative) | 17 | 21 | +4 |
| Detectors | 1 | 5 | +4 |
| Detection rules | 5 | 9 | +4 |
| Sample datasets | 1 | 2 | +1 |
| Parser event types | 9 | 9 | — |

**Implemented detectors after Day 2:** Bruteforce, Slow Bruteforce, Root Monitoring, PAM Correlation, Unknown Root Detection, Service Restart/Instability, Credential Compromise, Session Anomaly, Behaviour Correlation.

### Parser progress

Parser unchanged in scope (still 9 SSH event types) but hardened via robustness fixes. No new parsers added.

### Detection progress

Detection engine grew from 1 → 5 detectors. SSH detection coverage is now broad: brute force, service stability, credential compromise, behavioural correlation, and session anomalies. Threshold-band refinement remains outstanding.

### Engineering progress

All detectors integrated into `main.py`. Still no persistence layer, no `outputs/` writing, and no automated tests. Graphify output current.

---

## Current Status

**Estimated project completion:** ~28% (weighted across all 11 phases; V1 core is well underway)

**Current phase:** Phase 1 — SSH Monitoring Engine (~92%)

**Current focus:**
> Refining detector thresholds, adding event/alert persistence to `outputs/`, and preparing the normalized event schema for additional (non-SSH) log sources.

**Next milestone:**
- Persist parsed events and alerts to `outputs/` (Phase 5 kickoff)
- Refine detector threshold bands (service anomaly, credential compromise, behaviour)
- Begin Phase 2 second parser (Syslog or Authentication logs)

---

*Journal maintained day-by-day. Each working session appends a new Day section reconstructed from real commit history.*
