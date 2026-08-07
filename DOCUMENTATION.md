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

## Day 3

**Dates:** 2026-07-06 → 2026-08-05
**Commits:** 4 (`fde2b78`, `f70fab7`, `a6fcd44`, `6a942fa`)

### Summary

Day 3 closed the loop on the pipeline: alerts stopped being ephemeral stdout output and became persisted artifacts. An `outputs/` layer was added (`persistence.py`, `stats.py`), `main.py` was rewired to aggregate every detector's alerts into a single `all_alerts` list, compute run statistics, and write three JSON files. The engineering-documentation set was also completed — `ARCHITECTURE.md` and `SECURITY.md` were written from scratch and the development journal itself was committed. No parser or detector logic changed this day.

### Implemented features

- **Persistence layer** (`outputs/persistence.py`) — `save_events()`, `save_alerts()`, `save_statistics()` write `outputs/{events,alerts,statistics}.json`. A `json_serializer` hook converts `datetime` objects to ISO-8601 strings, since raw event dicts carry live `datetime` values.
- **Statistics generation** (`outputs/stats.py`) — `generate_statistics(events, alerts)` returns total event/alert counts, high/medium alert counts, and per-service and per-event-type breakdowns.
- **Alert aggregation in `main.py`** — each detector's alerts are now appended to a shared `all_alerts` list as they are printed, so statistics and persistence see the full result set rather than one detector's slice.
- **Architecture documentation** (`ARCHITECTURE.md`) — current vs. planned architecture, event/alert schemas, detector philosophy, state-management discussion, and the streaming/expiration design targeted in Phase 9.
- **Threat model** (`SECURITY.md`).
- **Development journal committed** — `DOCUMENTATION.md` (Days 1–2) entered the repo; `roadmap.md` was renamed to `ROADMAP.md` and refreshed alongside `README.md`.
- **Generated artifacts committed** — the current `ssh_dataset_v1` run's `outputs/*.json` were checked in, and `graphify-out/` was regenerated to include the new `outputs/` modules. `graphify-out/cache/**` was moved into `.gitignore`.

### Architecture decisions

- **Persistence separated from detection.** Detectors still just return alert lists; `main.py` owns aggregation and the `outputs/` layer owns serialization. Nothing in `detectors/` knows a file exists.
- **Serialization at the boundary, not in the parser.** Events keep native `datetime` objects all the way through detection (the time-window logic depends on it) and are only stringified by `json_serializer` on write.
- **Statistics as a derived artifact.** `generate_statistics()` takes the finished `events` and `all_alerts` lists rather than being fed incrementally — consistent with the batch model, and trivially replaceable when the engine goes stateful.
- **Outputs are regenerated, not appended.** Each run overwrites the three JSON files; there is no run history or alert deduplication yet.

### Lessons learned

- `datetime` in event dicts is free during detection and a problem at the boundary — a single `default=` serializer hook is cheaper than normalizing timestamps to strings earlier and re-parsing them in every detector.
- Aggregating alerts required touching every detector call site in `main.py`; the "new detector = three edits in main.py" cost is now visible and is an argument for a detector registry later.
- Committing generated `outputs/*.json` makes the artifacts reviewable in the repo, but they change on every run — worth revisiting if the diff noise outgrows the value.
- `generate_statistics()` buckets only `high` and `medium`, so `monitor` alerts are counted in `total_alerts` without a bucket of their own — a small reporting gap to close alongside the threshold-band refinement still outstanding from Day 2.

### Commits table

| Commit | Description |
|--------|-------------|
| [fde2b78](https://github.com/AnkitB1405/Linux-Log-Parser/commit/fde2b78) | Renamed `roadmap.md` → `ROADMAP.md` |
| [f70fab7](https://github.com/AnkitB1405/Linux-Log-Parser/commit/f70fab7) | Added `ARCHITECTURE.md`, `SECURITY.md`, `DOCUMENTATION.md`; refreshed `README.md` and `ROADMAP.md` |
| [a6fcd44](https://github.com/AnkitB1405/Linux-Log-Parser/commit/a6fcd44) | **Persistence + statistics layer**; `main.py` aggregates all detector alerts into `all_alerts` |
| [6a942fa](https://github.com/AnkitB1405/Linux-Log-Parser/commit/6a942fa) | Committed generated `outputs/*.json`, regenerated `graphify-out/`, ignored `CLAUDE.md` |

### Metrics

| Metric | Day 2 | Day 3 | Δ |
|--------|-------|-------|---|
| Commits (cumulative) | 21 | 25 | +4 |
| Detectors | 5 | 5 | — |
| Detection rules | 9 | 9 | — |
| Parser event types | 9 | 9 | — |
| Output artifacts | 0 | 3 | +3 |
| Documentation files | 2 | 5 | +3 |

Current run against `sample_logs/ssh_dataset_v1.txt`: **62 events → 17 alerts** (3 high, 14 medium), all `service: ssh`.

### Parser progress

Unchanged — still 9 SSH event types, no edits to `parser/ssh_parser.py` this day. `parser/event_schema.py:create_event()` remains defined but unused; parsers still emit their own dict shape (Phase 4 unification still open).

### Detection progress

Unchanged in coverage — no new detectors, no threshold edits. The Day 2 band-shadowing issue (e.g. `credential_compromise.py` testing `>= 5` before `>= 8`, making the high branch unreachable) is still outstanding.

### Engineering progress

Persistence is live — the Outputs stage of the pipeline is no longer a gap. The project now has a complete documentation set (README, journal, roadmap, architecture, threat model). Still no automated tests and no streaming; Graphify output is current but remains unconnected to the alert pipeline.

---

## Day 4

**Dates:** 2026-08-06 → 2026-08-07
**Commits:** 2 (`982f42a`, plus the documentation commit carrying this entry)

### Summary

Day 4 closed **Phase 4**: the event schema is unified. `parser/event_schema.py:create_event()` had existed since early on but was never called — parsers built their own dicts inline, so the "normalized schema" was documentation rather than code. All nine SSH parsers now route through `create_event()`, and the shape they emit is the shape the detectors, statistics and persistence layers consume.

The second half of the day fixed a related gap that only became visible once events had identity: **no alert carried a timestamp, and no alert pointed at the log lines that produced it**. A run reported "bruteforce from 203.0.113.40" with no indication of *when*, and no way to get back to the evidence. Every alert now carries both. The first automated test in the project's history was added to pin the result set while these changes went in.

### Implemented features

- **Normalized event schema** (`parser/event_schema.py`) — `create_event()` now returns a fixed nine-field shape: `id`, `timestamp`, `log_source`, `host`, `event_type`, `severity`, `username`, `source_ip`, `details`.
  - `id` — short uuid4 hex, generated per event. This is what makes alert→evidence linking possible.
  - `host` — was being parsed out of the syslog line and thrown away; now retained, which matters as soon as more than one machine feeds the pipeline.
  - `username` / `source_ip` — promoted to top-level fields rather than living in `details`, because every detector correlates on one or both, and every log source on the roadmap carries them.
  - `details` — per-source extras (PAM `uid`/`euid`/`tty`/`ruser`, PAM failure `count`, session `initiated_by`) live here instead of widening the common shape for every future parser.
- **All nine parsers migrated** (`parser/ssh_parser.py`) — `parse_failed_login`, `parse_successful_login`, `parse_session_opened`, `parse_invalid_user`, `parse_connection_closed`, `parse_auth_failure`, `parse_multiple_failures`, `parse_service_started`, `parse_service_stopped` all return `create_event(...)`.
- **Three parser helpers extracted** — `parse_host()`, `parse_username()` (folds the repeated `... user X ...` vs `... for X ...` branching that had been copy-pasted across parsers), and `parse_key_values()` (PAM `key=value` token extraction, replacing per-field index arithmetic).
- **Alerts anchored in time and evidence** (all five detectors) — each detector now tracks `(timestamp, event_id)` pairs rather than bare timestamps, so every alert gains:
  - `timestamp` — taken from the contributing log events, **not** wall-clock time. An alert about a 2019 log says 2019.
  - `event_ids` — the ids of the exact events that triggered it.
- **Field rename propagated** — `event["service"]` → `event["log_source"]` across all five detectors and `outputs/stats.py`.
- **First automated test** (`test_detectors.py`) — plain `assert` statements, no framework, runnable as `python3 test_detectors.py`. Pins:
  - the full 17-alert result set as `(alert_type, entity, severity)` triples
  - the event-type mix (62 events across 8 types)
  - the normalized event shape on every event, plus `log_source == "ssh"` and `host == "Sentinel"`
  - event id uniqueness
  - zero parser errors on a known-good dataset
  - **that no alert predates its own evidence** — a cheap invariant that would have caught the timestamp work being wired up backwards

### Architecture decisions

- **`create_event()` became the contract, not a suggestion.** The alternative was to delete it and accept inline dicts as the real schema. Routing through it was chosen because the next four parsers (syslog, auth, docker, web) each need the same shape, and a shared constructor is the cheapest place to enforce that — a second parser that quietly emits `user` instead of `username` breaks every detector silently.
- **`username` and `source_ip` are top-level; everything source-specific is in `details`.** The test is whether a field is something a *detector correlates on*. Those two are; PAM `tty` is not.
- **Alert timestamps come from the log, not from the clock.** Batch analysis of historical logs is the primary use case, so wall-clock time on an alert would be actively misleading. The alert is timestamped with the latest contributing event, which is also the moment the condition became true.
- **Evidence is stored as ids, not embedded events.** Keeps `outputs/alerts.json` small, keeps a single source of truth in `events.json`, and matches how a real SIEM references raw events.
- **The test pins behaviour, not implementation.** It asserts the alert set and event shape — the things a threshold change or a parser regression would move — and says nothing about how detectors are written internally.

### Bugs fixed

- **`detectors/behavior.py` — leaked loop variable.** The alert's service field was read as `event.get("service")` *after* the parse loop had ended, so it silently reported the log source of the last event in the file rather than the events the alert was about. Harmless while every event was SSH; wrong the moment a second parser lands. Replaced with a per-IP `log_sources` dict populated during the loop.

### Lessons learned

- A schema that nothing calls is a comment. `create_event()` had been "the normalized shape" in `ARCHITECTURE.md` for two days while every parser ignored it — the divergence cost nothing until it was time to add a second source, which is exactly when it would have cost the most.
- Giving events identity was the unlock. Alert timestamps, evidence links, and future deduplication are all downstream of "events have ids", and none of them were buildable before.
- Writing the test first would have been cheaper than writing it alongside. Its one failure during this work was a transcription error in the expected set, not a code regression — but confirming that meant diffing against the previous committed `outputs/alerts.json`, which only worked because those artifacts had been committed on Day 3.
- Refactoring five detectors at once is only safe with a pinned result set. The field-level diff against the Day 3 baseline (`pre-existing fields identical on every alert: True`) is what made this a mechanical change rather than a leap of faith.

### Commits table

| Commit | Author | Description |
|--------|--------|-------------|
| [982f42a](https://github.com/AnkitB1405/Linux-Log-Parser/commit/982f42a) | AnkitB1405 | **Schema unification** — all parsers route through `create_event()`; alerts gain `timestamp` + `event_ids`; `test_detectors.py` added |
| *(this entry)* | Claude | Day 4 journal, regenerated `outputs/*.json` and `graphify-out/`, `.gitignore` update |

> From Day 4 onward the journal records commit authorship. Source code — schema, parsers, detectors, tests — is authored by AnkitB1405. Documentation, generated artifacts and housekeeping commits are authored by Claude. Both are committed by AnkitB1405.

### Metrics

| Metric | Day 3 | Day 4 | Δ |
|--------|-------|-------|---|
| Commits (cumulative) | 25 | 27 | +2 |
| Detectors | 5 | 5 | — |
| Detection rules | 9 | 9 | — |
| Parser event types | 9 | 9 | — |
| Parsers using `create_event()` | 0 / 9 | 9 / 9 | +9 |
| Alerts with a timestamp | 0 / 17 | 17 / 17 | +17 |
| Alerts linked to source events | 0 / 17 | 17 / 17 | +17 |
| Automated tests | 0 | 1 | +1 |

Current run against `sample_logs/ssh_dataset_v1.txt`: **62 events → 17 alerts** (3 high, 14 medium), 0 parser errors — identical to Day 3, by design.

### Parser progress

Still 9 SSH event types — scope deliberately unchanged so the schema migration could be verified against a fixed result set. The parser is now, however, *ready* for a second source: `create_event()` is the single place a new parser plugs into, and the three new helpers are source-agnostic. The 1900-year timestamp limitation remains, now carried as an explicit `ponytail:` comment at `parser/ssh_parser.py:15` naming the fix (year from file mtime, or consume `journalctl -o short-iso`).

### Detection progress

Coverage unchanged by design; **capability** materially improved. Every alert is now auditable — it says when it fired and which log lines justified it, which is the difference between a demo and something usable during an actual incident. Threshold-band refinement is still outstanding and now has a safety net: `test_detectors.py` will fail loudly on any band change, which is exactly the behaviour wanted for a deliberate edit.

### Engineering progress

The project has automated tests for the first time. The pipeline is schema-clean end to end: parse → normalized event → detect → timestamped, evidence-linked alert → persist. Phase 4 is complete, which unblocks Phase 2 (additional parsers) — the schema was the real dependency under both the remaining parsers and the dashboard.

---

## Current Status

**Estimated project completion:** ~40% (weighted across all 11 phases; V1 core is well underway)

**Current phase:** Phase 1 — SSH Monitoring Engine (~95%); **Phase 4 (schema normalization) complete**; Phase 5 (Outputs) underway

**Current focus:**
> Phase 4 is closed. Next is the second parser now that the schema can absorb one, plus the outstanding severity-band fixes.

**Next milestone:**
- Fix the shadowed severity bands — `credential_compromise.py` tests `>= 5` before `>= 8`, so the `high` branch is unreachable (output-neutral on the current fixture, but a real hydra run trivially exceeds 8 and would still be reported `medium`)
- Fix the duplicate medium+high `behavior_anomaly` on a single IP (`behavior.py`)
- Begin Phase 2 second parser (Syslog or Authentication logs) against the normalized schema
- Parse `Accepted publickey` — currently unmatched by `identify_event()`, so key-based logins (including a stolen-key login present in the sample set) produce no event at all
- Give `monitor`-severity alerts their own bucket in `generate_statistics()`
- Validate against real attack traffic from the Metasploitable homelab VM once provisioned

---

*Journal maintained day-by-day. Each working session appends a new Day section reconstructed from real commit history.*
