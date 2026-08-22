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

## Day 5

**Dates:** 2026-08-19
**Commits:** 2 (`100a2ed`, `35dce82`), plus the documentation commit carrying this entry

### Summary

Day 5 replaced the parsing strategy itself. Since Day 1 the SSH parser had worked by splitting a line on whitespace and counting tokens — `parts[parts.index("from") + 1]`. That approach cannot express **optionality**, and real sshd output is full of it: the same event is written `for root` on one line and `for invalid user admin` on the next. Each such variant had been absorbed by a hand-written `if "user" in parts` branch, and every variant nobody had anticipated produced silently wrong data rather than an error.

The parser now matches compiled regular expressions. It is split into two layers: an **envelope** pattern that peels off the syslog wrapper (timestamp, host, process), and a **message table** of one pattern per event type matched against the remaining message body. 248 lines became 138, `.split()` and index arithmetic disappeared from the codebase entirely, and the pipeline output is unchanged — 62 events, 17 alerts, byte-identical to Day 4.

The split matters beyond tidiness. The message body is printed by OpenSSH's own source code, so it reads the same on every distribution; the envelope is the only part that varies by operating system. That is the property that makes the second, third and fourth log sources cheap rather than a rewrite each time.

### Implemented features

- **Envelope pattern** (`SYSLOG`) — one regex splits every line into `timestamp`, `host`, `process` and `message`. Replaces `parse_timestamp()`'s and `parse_host()`'s independent re-splitting of the same line. The optional `[pid]` group means the same pattern matches both journald short output (`sshd-session[200020]`) and classic BSD syslog (`sshd[3456]`), so pre-systemd machines need no second envelope.
- **Message pattern table** (`SSH_PATTERNS`) — nine rows of `(event_type, compiled_pattern)`, matched against the message body only. Replaces the ordered `elif "..." in line` chain in `identify_event()`. Adding an event type is now adding a row of data, not inserting a branch at the correct position in control flow.
- **Named-group → schema convention** — groups called `username` and `source_ip` are promoted onto the event; every other named group falls into `details` automatically. `session_opened`'s `initiated_by` and `multiple_auth_failures`' `count` arrive there with no per-parser code.
- **Optional groups absorb line variants** — `(?:invalid user )?` and `(?:(?:invalid|authenticating) user )?` collapse the hand-written branches that used to compute different token offsets for each shape.
- **Pattern ordering is no longer load-bearing.** The chain previously required `"more authentication failures"` to be tested before `"authentication failure"`, since the second substring is contained in the first. The `authentication_failure` pattern now requires a `pam_x(...):` prefix that the PAM count line does not have, so neither row can claim the other's lines regardless of order.
- **PAM context scanned for pairs, not positions** — `KEY_VALUE.findall()` replaces the twelve-line `parse_key_values()` helper. PAM does not guarantee key order, so scanning for `key=value` pairs is correct where any positional read would be a guess.
- **AI assistance statement** (`README.md`) — records that Claude is used for documentation, research, learning and debugging only, and that the split commit authorship in this repository reflects that.

### Architecture decisions

- **The envelope is separated from the message because they have different authors.** The operating system writes the wrapper; the application writes the body. They vary independently, so parsing them together means an OS change breaks application parsing and vice versa. Separated, a new machine costs one envelope row and a new application costs one message table — and `process` is the field that dispatches between tables once a second source lands.
- **A table of patterns, not a chain of conditions.** The if-chain encoded event identification as control flow, where correctness depended on statement order and a new event type meant editing a function. As data, order stops mattering, the nine event types are visible in one glance, and Docker or Apache become a new list rather than a new function.
- **Patterns describe shapes specific enough to reject wrong answers.** `\S+` matches anything non-blank, so it will happily capture the word `port` as an IP address — which is precisely how the old parser produced `source_ip="port"`. Constraining `source_ip` to `[0-9a-fA-F.:]+` in the `connection_closed` row lets the engine backtrack: the optional username group takes the IP first, fails to match `port` as an address, gives it back, and correctly reports no username. The pattern finds the right reading on its own.
- **`Accepted publickey` remains unmatched, deliberately.** It was measured — enabling it adds 2 events and changes no alerts — but this system monitors a machine that runs password authentication by choice, as a deliberate second factor against physical access to the laptop. Parsing an authentication method the environment does not use would be scope without purpose. The row is one word away (`password` → `password|publickey`) and carries a comment saying so, for whenever a key-authenticated host does enter scope.
- **A refactor commit proves it changes nothing.** The conversion was verified against the committed Day 4 artifacts before commit: identical alert set, identical event mix, zero parser errors. The only intentional difference is that PAM `details` now carry `logname` and `ruser`, because the pair scan is general where the old helper took a fixed key list.

### Bugs fixed

All four were latent — none could fire on the sample dataset, and all four would have fired on real `journalctl` output. Measured against the same six real-world line variants, the old parser was correct on 2; the new parser is correct on 6.

- **`Connection closed by authenticating user root 192.0.2.1`** — reported `username="authenticating"`, `source_ip="user"`. The `authenticating user` prefix was never handled; only `invalid user` was.
- **`Connection closed by invalid user admin 192.0.2.2`** — reported `username="user"`, `source_ip="admin"`. The `if "invalid" in parts` branch shifted the offsets by one too few.
- **`Connection closed by 192.0.2.7 port 54327`** — reported `username="192.0.2.7"`, `source_ip="port"`. The no-username form was not anticipated at all.
- **`Invalid user from 192.0.2.6 port 54326`** — reported `username="from"`. Same cause: `parts.index("user") + 1` lands on the next token whether or not a username is present.

None of these raised an exception. Each produced a well-formed event containing plausible nonsense, which then flowed into detector correlation — `source_ip="user"` would have accumulated in `failed_attempts` and eventually raised a brute-force alert against an "IP address" named `user`.

### Lessons learned

- **A fixture written alongside its parser tests nothing.** `ssh_dataset_v1.txt` contains only the simplest form of each line, because it was authored while the parser was authored — the two agreed by construction. The test suite passed at 100% while four line shapes from any real server would have been parsed into garbage. A test built from the same assumptions as the code cannot falsify those assumptions.
- **Silent wrongness is worse than a crash.** Every one of the bugs above returned a valid-looking event. A `ValueError` on line 1 would have been found on Day 1; instead the errors were invisible until the parser was pointed at output it had never seen.
- **Optionality was the missing primitive.** Every `if "user" in parts` in the old parser was a hand-rolled, single-case version of `(?:...)?` — written once per variant somebody happened to encounter. The regex expresses the whole class in four characters, including the variants nobody enumerated.
- **The conversion was a deletion.** 248 lines to 138, twenty `.split()`/`.index()` call sites to zero, nine functions to one loop. Regex is usually argued for on power; here the stronger argument was less code to be wrong in.
- **Knowing where not to apply it matters as much.** PAM `key=value` context and Docker's JSON log driver are both better served by pair-scanning and `json.loads` respectively. Converting everything to regex on principle would have made the PAM path worse.

### Commits table

| Commit | Author | Description |
|--------|--------|-------------|
| [100a2ed](https://github.com/AnkitB1405/Linux-Log-Parser/commit/100a2ed) | AnkitB1405 | **Regex conversion** — envelope pattern + message table replace token-index parsing and the ordered if-chain; 248 → 138 lines, output unchanged |
| [35dce82](https://github.com/AnkitB1405/Linux-Log-Parser/commit/35dce82) | Claude | AI assistance statement in `README.md`, root `__pycache__` ignored, regenerated `outputs/*.json` and `graphify-out/` |
| *(this entry)* | Claude | Day 5 journal, `ROADMAP.md` and `README.md` refresh, `journal/regex_lab.py` |

### Metrics

| Metric | Day 4 | Day 5 | Δ |
|--------|-------|-------|---|
| Commits (cumulative) | 28 | 30 | +2 |
| `parser/ssh_parser.py` lines | 248 | 138 | −110 |
| Parser functions | 12 | 2 | −10 |
| `.split()` / `.index()` call sites | 20 | 0 | −20 |
| Compiled patterns | 0 | 11 | +11 |
| Real-world line variants parsed correctly | 2 / 6 | 6 / 6 | +4 |
| Parser event types | 9 | 9 | — |
| Detectors | 5 | 5 | — |
| Detection rules | 9 | 9 | — |
| Automated tests | 1 | 1 | — |

Current run against `sample_logs/ssh_dataset_v1.txt`: **62 events → 17 alerts** (3 high, 14 medium), 0 parser errors — unchanged from Day 4, which was the point.

### Parser progress

Still nine SSH event types; the scope was held fixed so the strategy change could be proven output-neutral. What changed is what the parser can survive. The old implementation fit one machine's log formatting because it was written against one machine's sample file; the new one describes what OpenSSH prints, which is the same text on Kali, Linux Mint and Ubuntu 8.04 alike. The 1900-year timestamp limitation remains, now with a cheaper fix available: `journalctl -o json` supplies `__REALTIME_TIMESTAMP` in microseconds since epoch, which removes the missing-year problem rather than working around it.

### Detection progress

Unchanged by design — no detector was touched. The indirect gain is input quality: four classes of malformed event can no longer reach the correlation stage, which removes a category of false positive that would have appeared the first time this ran against a live host rather than the fixture.

### Engineering progress

The parser is now the shape the roadmap needs. Phase 2 (additional parsers) was previously blocked twice over — once on the schema, closed on Day 4, and once on parsing strategy, since a token-index parser cannot read Apache's combined log format at all: a quoted request and a free-form user-agent break any fixed token offset. Both blockers are now gone, and a second source costs one pattern table.

---

## Day 6

**Dates:** 2026-08-21 → 2026-08-23
**Commits:** 6 (`bd01e9d`, `da66712`, `22e4f57`, `d83f7bc`, `17661f8`, `0bc62d2`), plus the documentation commit carrying this entry

### Summary

Day 6 turned a single-source SSH tool into a multi-source engine. Three things happened, in order.

First, the SSH parser stopped being written for one machine. Day 5 split parsing into an envelope layer and a message layer; Day 6 used that split for what it was for, adding a second envelope so the parser reads Linux Mint's RFC3339 `auth.log` as well as journald's BSD format. Which envelope matches is how the format is detected — nothing declares it. A companion module answers the other half of the question, working out at runtime which log *this* machine keeps.

Second, Phase 1 was closed out. Two severity-band bugs turned out to be the same mistake twice, and a third gap left an entire severity tier uncounted.

Third, Docker landed — parser, two detectors, fixture, and wiring into the pipeline. The parser deliberately does not use regex, one day after the migration that introduced it.

The run is now **148 events from two sources producing 20 alerts**, verified to be exactly what the two sources produce independently.

### Implemented features

- **Second envelope, and format auto-detection** (`parser/ssh_parser.py`) — `ENVELOPES` is a table of `(name, timestamp_parser, pattern)` tried in order. `rfc3339` reads Linux Mint's `auth.log` (`2026-08-19T10:09:15.247212+05:30`) with a real year and offset; `bsd` reads journald short output and classic syslog. A file mixing both parses correctly line by line.
- **Machine detection** (`parser/log_source.py`) — `detect_ssh_log()` prefers `/var/log/auth.log` where it exists and is readable, falling back to `journalctl`. Kali ships no `auth.log`; Mint and Metasploitable do. `read_lines()` drops journald's own `-- Boot … --` and `-- No entries --` markers, which are not log lines and would otherwise be counted as parse failures.
- **Live mode** — `python3 main.py --live` reads this machine's real SSH log instead of the fixture. A plain run is unchanged, so the pinned test stays reproducible.
- **Four new SSH event types** — `session_closed`, `max_auth_attempts`, `user_unknown`, `preauth_failure`. The last covers scanner traffic (connection reset, bad banner, refused key exchange) and is deliberately *not* called brute force: no credential was offered.
- **PAM `user=` promoted to `username`** — PAM is where root targeting is actually named, and it was being buried in `details`.
- **Quoted `key=value` parsing** — dockerd writes logrus context whose values contain spaces. The previous `(\w+)=(\S*)` truncated `msg="Daemon has completed initialization"` to `"Daemon`. Now `(\w+)=("[^"]*"|\S*)`, quoted form first.
- **Docker events parser** (`parser/docker_parser.py`) — `json.loads` plus an `ACTIONS` table on `(Type, Action)`. 84/84 captured events parse, with real epoch timestamps.
- **Three new detectors** — `auth_anomaly` (a successful login by an unsanctioned method), `container_anomaly` (`docker exec`, health-check probes suppressed), `container_escape` (HostConfig assessed for routes onto the host).
- **Multi-source pipeline** (`main.py`) — both sources parsed into one event list, every detector run over it.
- **Detector registry** (`detectors/registry.py`) — one list, imported by both the pipeline and the test.
- **Redacted Docker fixture** (`sample_logs/docker_events_v1.jsonl`) — 84 events captured from the real homelab.

### Architecture decisions

- **The Docker parser is not regex, one day after the regex migration.** `docker events` emits JSON; something already did the parsing. Re-deriving that structure with patterns would be slower and would break on any value containing a brace or a quote. The envelope/message split still holds — JSON structure is Docker's envelope, `ACTIONS` is its message table. The general rule: regex is for text written to be *read*; `json.loads` is for text written to be *parsed*. Neither `parse_key_values` (PAM) nor the JSON path was converted to regex on principle, because that would have made both worse.
- **`Accepted publickey` is parsed as an anomaly, not accepted as a login.** It had been excluded on the grounds that password auth is the only method in use. That reasoning was inverted: because key auth is never configured on any of these machines, a *successful* publickey login means a key exists that nobody installed, which is how an intruder keeps access after a break-in. The parser must match it precisely so a detector can raise on it.
- **Missing evidence produces silence, not reassurance.** `container_escape` skips events with no `host_config` rather than treating them as safe. A detector that quietly passes un-enriched containers is worse than one that does not run, because it looks like coverage.
- **Privilege is a state, not an event.** Portainer holds `/var/run/docker.sock` every second of every day, legitimately. Alerting on the state means alerting on the homelab's own infrastructure forever, which is how a detector gets muted. `ALLOWED` records expected findings per container and only unexpected ones raise — keyed on container **name**, because compose destroys and recreates containers and ids change on every `up`.
- **Ordinary data volumes stay silent.** Six of the homelab's ten containers bind-mount `/docker/*` or `/nas/*`; that is how Docker persistence normally works. Only sensitive host paths raise, and read-only mounts of them do not — reading `/etc` is a much smaller thing than rewriting it.
- **Enrichment belongs in the collector, not the parser.** `docker inspect` needs a live daemon and a network call per container. Keeping parsers as pure text→event functions is what lets them be tested against a fixture and run against archived captures.
- **The learning material left the repository.** `journal/` is gitignored. The labs restate logic that lives for real in `parser/`, and a second copy of a pattern table drifts out of sync with the first.

### Bugs fixed

- **`credential_compromise` — `high` was unreachable.** Bands were ordered `if recent >= 5 … elif recent >= 8`, so a burst of twelve failures reported `medium`. Output-neutral on the fixture; a real hydra run trivially exceeds eight.
- **`behavior` — one IP, two verdicts.** Two plain `if` statements rather than a chain, so four or more suspicious windows raised a `medium` *and* a `high` citing identical evidence.
- **Both had the same root cause.** Each band carried its own copy of the alert dict, which let the two branches drift apart. Both are now ordered `BANDS` tables feeding one shared dict, so a threshold change cannot be applied to one branch and missed in the other.
- **`generate_statistics` dropped a whole severity.** Only `high` and `medium` had buckets; `monitor` alerts landed in `total_alerts` and nowhere else. Counting is now by severity name, so an unlisted severity gets a bucket instead of vanishing.
- **The test had drifted from the pipeline.** `test_detectors.py` held its own copy of the detector list, and `container_anomaly` had been added to `main.py` but not to it — the test was silently no longer covering a detector that was running. Both now import `detectors/registry.py`.
- **journald markers counted as parse failures.** `-- Boot 3f2a… --` and `-- No entries --` are journalctl's own output, not log lines.

### Lessons learned

- **The same shape of bug appeared four times in one sprint.** Two unreachable severity bands, a missing statistics bucket, and a test that had stopped covering a detector — every one caused by the same fact being written down twice and the copies drifting. Each fix was to remove the duplication, not to correct the copy. Where a list must exist twice, it should exist once and be imported.
- **Knowing what a log does *not* contain is worth as much as parsing what it does.** The most valuable finding of the Docker work was negative: `Privileged`, `PidMode`, `docker.sock` and `Binds` appear zero times across 84 events, despite containers being started with all of them while the capture ran. No amount of parser work would have found them, and only running code against real data revealed it.
- **A detector that fires on normal operation is a detector that gets deleted.** Health-check execs and Portainer's socket mount are both completely routine, and both would trigger the obvious rule constantly. Suppression and baselining are not refinements to add later; without them neither detector would survive its first night.
- **Reference data from an idle machine is worse than none.** The local Docker daemon has never run a container, so its logs would have produced a parser fitted to nothing. Every Docker finding in this sprint came from a capture taken on the machine that actually runs the workload.
- **A stated reason can be right while its conclusion is wrong.** `Accepted publickey` was excluded because key auth is never used. That is true, and it is precisely why the line matters — the correct response was to parse it and alert, not to ignore it.

### Commits table

| Commit | Author | Description |
|--------|--------|-------------|
| [bd01e9d](https://github.com/AnkitB1405/Linux-Log-Parser/commit/bd01e9d) | AnkitB1405 | Multi-envelope SSH parsing, machine detection, `--live` mode, four new event types, PAM `user=` promotion, `auth_anomaly` detector |
| [da66712](https://github.com/AnkitB1405/Linux-Log-Parser/commit/da66712) | AnkitB1405 | Docker events parser, `container_anomaly` detector, both severity-band fixes, `monitor` statistics bucket |
| [22e4f57](https://github.com/AnkitB1405/Linux-Log-Parser/commit/22e4f57) | Claude | Redacted 84-event Docker fixture, refreshed outputs |
| [d83f7bc](https://github.com/AnkitB1405/Linux-Log-Parser/commit/d83f7bc) | Claude | `journal/` gitignored — learning labs kept local |
| [17661f8](https://github.com/AnkitB1405/Linux-Log-Parser/commit/17661f8) | AnkitB1405 | Multi-source pipeline, detector registry, quoted `key=value`, `container_escape` assessment |
| [0bc62d2](https://github.com/AnkitB1405/Linux-Log-Parser/commit/0bc62d2) | Claude | Outputs refreshed for the merged pipeline |
| *(this entry)* | Claude | Day 6 journal, `ROADMAP.md`, `README.md` and `SECURITY.md` refresh |

### Metrics

| Metric | Day 5 | Day 6 | Δ |
|--------|-------|-------|---|
| Commits (cumulative) | 31 | 37 | +6 |
| Log sources | 1 | 2 | +1 |
| Parsers | 1 | 2 | +1 |
| Envelope formats | 1 | 2 | +1 |
| Detectors | 5 | 8 | +3 |
| SSH event types | 9 | 13 | +4 |
| Docker event types | 0 | 15 | +15 |
| Events per run | 62 | 148 | +86 |
| Alerts per run | 17 | 20 | +3 |
| Real captured events under test | 0 | 84 | +84 |

Current run: **148 events (64 ssh, 84 docker) → 20 alerts** (6 high, 14 medium), 0 parser errors.

### Parser progress

Two sources, two very different parsing strategies, one event shape. The SSH parser reads two envelope formats and thirteen event types; the Docker parser reads JSON and fifteen. Neither knows the other exists, and no detector can tell which produced an event — `create_event()` is what makes that true.

The 1900-timestamp limitation now applies only to the BSD path. The Mint homelab, which is the always-on install, carries real years and offsets throughout.

### Detection progress

Coverage moved from one attack surface to two. SSH detection gained a genuine new class — an unsanctioned authentication method, which is a persistence indicator rather than an intrusion attempt — and Docker arrived with two detectors covering container access and container configuration.

Both Docker detectors are built around suppression, because both would otherwise fire constantly on normal operation. That was the central design problem, not an afterthought.

`container_escape` is complete as judgement and unproven as plumbing: it is tested against real captured `HostConfig` shapes and the homelab's real bind layouts, but has never seen a live enriched event, because the collector that would attach them does not exist yet.

### Engineering progress

Phase 1 is closed. Phase 2 has its first non-SSH source in the pipeline, which was the milestone the schema (Day 4) and the regex conversion (Day 5) were both prerequisites for — a second source cost a pattern table and a detector, not a rewrite.

The recurring engineering lesson of this sprint was about duplication: four separate defects, all caused by one fact recorded twice. The detector list, the severity bands and the statistics buckets each now exist once.

---

## Current Status

**Estimated project completion:** ~50% (weighted across all 11 phases)

**Current phase:** **Phase 1 complete**; Phase 2 (Additional Parsers) ~30%; Phase 3 (Detection Expansion) ~55%; Phase 5 (Outputs) 50%

**Current focus:**
> Two log sources are in the pipeline and eight detectors run over the merged stream. The next dependency is the Docker events collector, which unblocks both the live feed and container-escape enrichment.

**Next milestone:**
- **Docker events collector** — `docker events` is in-memory only and lost on daemon restart, so nothing can be read retroactively. Blocks the live feed *and* `container_escape`, which is written but cannot fire without HostConfig enrichment
- Validate the SSH parser against the homelab's real `auth.log` (`python3 main.py --live` on the Mint box)
- `docker inspect` enrichment in the collector, cached by container id
- Re-key `service_anomaly` on service identity — it buckets on `log_source`, which is `docker` for every container, so three containers restarting once each would read as instability
- Replace `KNOWN_ROOT_IPS` with trust tiers (tailnet / LAN / public)
- Historical retention (Phase 5) — the hidden dependency under the dashboard, the AI layer, lateral movement, and real escape baselining

**Closed, not deferred:**
- Mixed 1900/real-year timestamps across machines. One copy of the project runs on each device and reads only that device's own log, so logs are never merged across machines. The always-on Mint install uses the RFC3339 path and has real years throughout.

---

*Journal maintained day-by-day. Each working session appends a new Day section reconstructed from real commit history.*
