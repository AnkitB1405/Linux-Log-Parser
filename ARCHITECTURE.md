# Architecture — Homelab Log Parser (Linux)

**Status:** implemented unless a section says otherwise. Planned work is
confined to the two sections at the end and is labelled as such.

Three log sources feed one normalized event stream that nine detectors read.
A run is 1,772 lines of stdlib Python — no dependencies, no framework, no
database.

---

## The shape of a run

```
    log lines                       (three sources, three formats)
        │
        ▼
    PARSERS         ssh_parser · docker_parser · web_parser
        │           each answers only for the source it understands
        ▼
    create_event()  the one place an event is constructed
        │
        ▼
    events[]        one list, one shape, source-agnostic
        │
        ▼
    DETECTORS       nine, each filtering by event_type
        │
        ▼
    alerts[]        severity, evidence, recommended action
        │
        ▼
    outputs/*.json  events · alerts · statistics
```

`main.py` is the whole orchestration and holds no logic of its own: it reads
each source, hands lines to the matching parser, runs every detector in
`detectors/registry.py` over the merged list, and persists the result.

**Batch, in memory.** The full event list is held at once and every detector
scans it. Streaming is Phase 9 and is not built.

---

## Two decisions everything else rests on

### 1. One event shape, constructed in one place

`parser/event_schema.py:create_event()` is the only constructor. Every parser
returns its output. Nine fields, always present:

```python
{
    "id":         "b1c2a0054d24",     # short uuid4 — what alerts point at
    "timestamp":  datetime(...),      # from the log line, never wall clock
    "log_source": "ssh",              # ssh | docker | web
    "host":       "Sentinel",
    "event_type": "failed_login",
    "severity":   None,               # detectors set this, parsers never do
    "username":   "guest",
    "source_ip":  "198.51.100.10",
    "details":    {}                  # everything source-specific
}
```

`username` and `source_ip` are promoted to the top level because every
detector correlates on one or both. Everything else lives in `details`, so a
new parser never widens the common shape.

This is why a second and third log source cost a pattern table each rather
than a rewrite: **no detector contains the words "ssh" or "docker"**. They
read `event_type`, `source_ip`, `timestamp`. When the Docker parser landed,
zero detectors changed.

Two honest exceptions. `web_anomaly` gates on `log_source == "web"` because
several of its event types could plausibly be emitted by a future source and it
should not claim them. `service_anomaly` *buckets* on `log_source`, which is
too coarse now that Docker exists — every container collapses into one
"docker" bucket, so three unrelated containers restarting once each read as
instability. That is a known defect, not a design.

A source that genuinely has no value for a promoted field leaves it `None`.
Docker events carry neither a user nor an address; inventing one would be
worse than an empty field.

### 2. Envelope and message are parsed separately

A syslog line has two halves written by two different programs:

```
Aug 19 10:09:15 shadow sshd[3344602]: Failed password for root from 45.155.205.211
└──────────── ENVELOPE ────────────┘  └──────────── MESSAGE ──────────────────┘
     written by the OS                       written by OpenSSH
```

They vary independently. The envelope changes when you change machine; the
message changes only when the application itself changes, which is almost
never and identically across distributions.

So a new **machine** costs an envelope row, and a new **application** costs a
message table. Neither costs a parser.

---

## Parsers

| Module | Reads | Strategy |
|---|---|---|
| `parser/ssh_parser.py` | sshd via journald or `auth.log` | regex — envelope table + 16-row message table |
| `parser/docker_parser.py` | `docker events --format '{{json .}}'` | `json.loads` + action table |
| `parser/web_parser.py` | Apache/Nginx access and error logs | regex — quoted-field aware |
| `parser/log_source.py` | — | works out which log *this machine* keeps |

### Why they don't all use regex

Regex is for text written to be **read**. `json.loads` is for text written to
be **parsed**.

Docker emits JSON, so re-deriving that structure with patterns would be slower
and would break on any value containing a brace or quote. The envelope/message
split still holds there — JSON structure is Docker's envelope, and the
`(Type, Action)` table is its message layer.

PAM's `key=value` context is likewise scanned for pairs rather than matched
positionally, because PAM does not guarantee key order.

### Format and machine auto-detection

Two separate questions, answered separately.

**Which format is this line?** `ENVELOPES` is an ordered table of
`(name, timestamp_parser, pattern)`; the first to match wins. Nothing declares
the format, and a file mixing formats parses line by line.

| Envelope | Shape | Machines |
|---|---|---|
| `rfc3339` | `2026-08-19T10:09:15.247212+05:30 host sshd[123]:` | Linux Mint homelab — the primary target |
| `bsd` | `Aug 19 10:09:15 host sshd-session[123]:` | Kali (journald short), Metasploitable (classic syslog) |

RFC3339 carries a real year. BSD does not, so those timestamps resolve against
a reference point — the log file's mtime — with December→January rollover
handled explicitly.

**Which log does this machine keep?** `parser/log_source.py:detect_ssh_log()`
prefers `/var/log/auth.log` where it exists and is readable, and falls back to
`journalctl`. Mint and Metasploitable have the file; Kali ships none.

One copy of the project runs on each device and reads only that device's logs.
There is no multi-host correlation, and logs are never merged across machines.

### A parser only answers for what it understands

`auth.log` is not an SSH log. It is the authentication log, shared with cron,
sudo, dovecot and anything else touching PAM. `ssh_parser` therefore refuses
lines whose envelope names a process outside
`{sshd, sshd-session, sshd-auth, systemd}`.

Without that check, real data produced 1,224 events labelled `log_source:
"ssh"` from a file containing no sshd at all — cron jobs as SSH sessions, a
mail brute force as SSH authentication failure. Silent, confident, and wholly
wrong.

---

## Detectors

Contract: `detect_x(events) -> [alert dicts]`. One file, one concern, stateless
across runs, never calls another detector. `detectors/registry.py` holds the
list, imported by both `main.py` and the test so the two cannot drift.

| Detector | Watches | Correlates on |
|---|---|---|
| `bruteforce` | fast/slow brute force, root targeting, PAM bursts, unknown root login | source IP |
| `service_anomaly` | repeated service start/stop | service |
| `credential_compromise` | failure burst then success | (username, IP) |
| `behavior` | patterned activity across sliding windows | source IP |
| `session_anomaly` | sessions opening and closing in seconds | username |
| `auth_anomaly` | login by an authentication method these hosts never use | per event |
| `container_anomaly` | `docker exec` into a running container | container |
| `container_escape` | containers configured to reach the host | container |
| `web_anomaly` | scanning, web credential attack, repeated 5xx | source IP |

### Alerts

```python
{
    "severity":    "high",              # monitor | medium | high
    "alert_type":  "slow_bruteforce",
    "source_ip":   "203.0.113.40",
    "timestamp":   datetime(...),       # from the evidence, not the clock
    "event_ids":   ["7f3a...", ...],    # resolves against events.json
    "recommended_action": "block_ip and report",
}
```

`event_ids` is what makes an alert auditable — every alert can be traced back
to the exact lines that raised it, and the test asserts no alert predates its
own evidence.

### Detection is time-windowed, and the window slides

Every count is over a window, and the window is the **densest run anywhere in
the data**, found with two pointers.

This is not a detail. The window was previously anchored on the most recent
event, so only the tail of a log was ever examined. A labelled brute force of
286 failures in 222 seconds went entirely undetected because the last event in
that file was 24 hours later.

| Detector | Window | Bands |
|---|---|---|
| `bruteforce` — PAM | 180s | 1 signal → medium; ≥2 in window → high |
| `bruteforce` — root | 600s | ≥3 → medium; PAM-correlated → high |
| `bruteforce` — slow | 600s | ≥5 → medium; ≥8 → high |
| `service_anomaly` | 300s | ≥3 → medium; ≥5 → high |
| `credential_compromise` | 600s | ≥5 → medium; ≥8 → high |
| `behavior` | 1800s | ≥2 windows → medium; ≥4 → high |
| `session_anomaly` | ≤20s open→close | short session |
| `web_anomaly` — scanning | 60s | ≥8 → medium; ≥20 or named tool → high |
| `web_anomaly` — auth | 300s | ≥5 → medium; ≥10 → high |
| `auth_anomaly`, `container_*` | per event | — |

**Bands are ordered highest-first and mutually exclusive.** Three separate bugs
in this project were non-exclusive tiers — the same evidence raising two alerts,
or a `high` branch made unreachable by the `medium` test above it. Each was
caused by duplicated alert dicts letting the branches drift, so each detector
now has one alert dict fed by a bands table.

### Suppression is part of the design

Two detectors would be unusable without it, and both were found by real data:

- **Health-check execs.** Containers with a `HEALTHCHECK` exec a probe every
  few seconds forever, and the event stream does not mark them as probes.
  Suppressed on command pattern.
- **Expected privilege.** Portainer legitimately holds `/var/run/docker.sock`
  every second of every day. `container_escape` alerts on findings *not
  expected for that container*, keyed on container **name** — ids change on
  every `docker compose up`.

Likewise `web_anomaly` excludes curl, wget and python-requests from its
scanner list: those are generic clients, and treating automation as attack is
the same mistake.

---

## Outputs

`outputs/persistence.py` writes `outputs/{events,alerts,statistics}.json`.
`outputs/stats.py` counts by severity name, so an unlisted severity gets a
bucket rather than silently vanishing.

**These are rebuilt on every run.** There is no history, which is the single
largest structural gap — see below.

---

## Testing

`test_detectors.py`, plain asserts, no framework. It pins the alert set, the
event mix, the normalized shape, id uniqueness, and that no alert predates its
evidence — plus regression checks for specific bugs found in real data.

It runs the same detector list as `main.py` by importing the registry. An
earlier version kept its own copy and had already silently stopped covering a
detector that was running in production.

**Fixture provenance matters.** The Docker and web fixtures are real captured
data. The SSH fixture is synthetic and was written alongside the parser, which
means it agrees with it by construction and cannot falsify it. That asymmetry
is the reason for Phase 11.

---

## Known structural gaps

- **No history.** `outputs/*.json` are overwritten each run, so nothing can be
  compared over time. This blocks the dashboard, the AI layer, lateral-movement
  detection and real escape baselining.
- **Batch only.** The whole file is read, then processed, then the program
  exits. Nothing follows a live log.
- **Configuration is in code.** Thresholds, windows and two allowlists
  (`KNOWN_ROOT_IPS`, `ALLOWED`) are literals across six detectors.
- **Every detector rescans the full list.** Fine at fixture volume, and 57,000
  lines/sec on real data, but unbounded for a long-running process.
- **`container_escape` cannot fire yet.** It needs `docker inspect` enrichment
  that no collector produces, and correctly reports nothing rather than
  assuming un-enriched containers are safe.

---

## Planned — not implemented

**Streaming (Phase 9).** `log_source.py` already resolves the right input per
machine; streaming adds `journalctl -f` / `tail -F` and incremental detection.
That requires bounded state: expiring events past the widest window (1800s) and
dropping per-key state once a source goes quiet.

**Retention (Phase 5).** A durable store behind `persistence.py` so runs
accumulate instead of overwriting. Everything in the list above depends on it.

**External evaluation (Phase 11).** Measuring precision and recall against the
AIT Log Data Set's published labels, with tuning and holdout sets kept
separate. See `ROADMAP.md`.
