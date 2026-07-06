# Security Considerations — Homelab Log Parser (Linux)

Detection assumptions, threat model, and limitations for the log parsing and detection engine.

Status: 🚧 Educational / homelab-grade. This is **not** production-hardened detection tooling. This document is honest about what the engine can and cannot see today.

---

## Threat Model

**What the engine is designed to detect (SSH-focused, today):**

| Threat | Detector | Signal |
|--------|----------|--------|
| Fast SSH brute force | `bruteforce` | Many failed logins per IP in a short window |
| Slow / low-and-slow brute force | `bruteforce` | Failed logins spread over a 10-minute window |
| Root-targeting attacks | `bruteforce` | Failed logins against `root`; PAM correlation |
| PAM auth-failure bursts | `bruteforce` | `multiple_auth_failures` (PAM) signals |
| Unexpected root access | `bruteforce` | Successful `root` login from an IP not in `KNOWN_ROOT_IPS` |
| Service instability / tampering | `service_anomaly` | Repeated SSH service start/stop within 5 min |
| Credential compromise | `credential_compromise` | Burst of failures then a success on same user+IP |
| Distributed / patterned attacker behaviour | `behavior` | Multiple suspicious 30-min windows per IP |
| Session anomalies | `session_anomaly` | Session opened and closed within 20 seconds |

**Out of scope (today):** non-SSH log sources, kernel/network-level attacks, malware, container escapes, data exfiltration, log tampering that removes lines, and any host the parser has no logs for.

**Adversary assumption:** an unauthenticated or low-privileged remote attacker probing SSH, or an attacker whose activity is visible in standard `sshd`/PAM log output.

---

## Current Assumptions

- **Log integrity is trusted.** The engine assumes logs are complete and unmodified. An attacker who can edit or delete log lines can evade detection.
- **Timestamps are reliable and monotonic.** Parsing uses `%b %d %H:%M:%S` with **no year** — year is not present in standard syslog lines, so cross-year and DST edge cases are undefined.
- **Single host / single log file** per run. No multi-host correlation.
- **Known-good root IPs are correctly configured.** `KNOWN_ROOT_IPS` is a hardcoded allowlist in `detectors/bruteforce.py`; stale entries cause missed or false alerts.
- **Batch processing.** All events are loaded into memory and analyzed together; there is no live monitoring yet.
- **Local, offline operation.** No network calls, no external threat intel.

---

## Limitations

- **SSH only.** Docker, syslog, auth (sudo/su/passwd), and web server logs are not yet parsed.
- **No persistence.** Events, alerts, and detections are printed to stdout and lost on exit (`outputs/` not yet written).
- **No deduplication / alert state.** Re-running on the same data re-emits the same alerts.
- **Stateless across runs.** No memory of prior sessions; no historical baselining.
- **Threshold bands are coarse and, in places, mis-ordered.** In some detectors the higher-severity band is written after (and can be shadowed by) the lower band's condition — a known refinement target (see `DOCUMENTATION.md`, Day 2 lessons).
- **No authentication/authorization** around the tool itself; it is a local script.

---

## False Positives

Situations that may trigger alerts without a real attack:

- **Legitimate automation** (backup jobs, CI, config management) opening many short SSH sessions → `short_session` / behaviour alerts.
- **A new admin workstation** logging in as root from an IP not yet added to `KNOWN_ROOT_IPS` → `unknown_root_login`.
- **Planned service maintenance** restarting `ssh.service` repeatedly → `service_instability`.
- **Fat-fingered password entry** by a real user followed by success → `credential_compromise`.
- **Shared NAT / VPN egress IPs** where many users appear as one source IP → inflated per-IP counts.

Mitigation path: allowlists, per-source suppression windows, and dedup once persistence lands.

---

## False Negatives

Attacks the engine will likely miss today:

- **Attacks in unparsed log sources** (web, sudo, containers).
- **Credential stuffing that succeeds on the first try** (no failure burst to correlate).
- **Distributed brute force across many IPs** each staying under per-IP thresholds.
- **Log-tampering attackers** who delete their failed-login lines.
- **Attacks outside the detection windows** (e.g. brute force paced slower than the slow-BF window).
- **Non-password vectors** (key theft, session hijacking) that produce a clean `successful_login` from an allowlisted context.

---

## Parser Assumptions

- Log lines begin with `Month Day HH:MM:SS` (standard syslog prefix); `parse_timestamp` splits on the first three whitespace tokens.
- Event type is identified by **substring matching** on known `sshd`/PAM message fragments (`"Failed password"`, `"Accepted password"`, `"Invalid user"`, `"session opened"`, `"Connection closed"`, `"authentication failure"`, `"more authentication failures"`, `"Started ssh.service"`, `"Stopped ssh.service"`).
- Username/IP extraction is **positional/token-based** (`index("from")`, `index("user")`/`index("for")`), which assumes a stable field order. Non-standard `sshd` formats or localized messages may not parse.
- Unrecognized lines return `None` and are collected into an `errors` list rather than crashing.

---

## Synthetic Datasets

- Detection is currently validated against **synthetic** logs in `sample_logs/` (`ssh_dataset_v1.txt`, `sample_ssh_log.txt`), not live production logs.
- Synthetic data is crafted to exercise each detector, so measured "detection rate" reflects the fixtures, **not** real-world efficacy.
- No labelled ground-truth benchmark or precision/recall measurement exists yet.
- Real `sshd`/PAM logs will contain formats and edge cases not represented in the fixtures.

---

## Roadmap for Production Readiness

Ordered, roughly by dependency:

1. **Persistence** — write events/alerts/detections to `outputs/` with dedup and alert IDs.
2. **Unified event schema** — UUIDs, `source`, `host`; route parsers through `create_event`.
3. **Threshold correction & tuning** — fix band ordering; make thresholds configurable, not hardcoded.
4. **Config over code** — move `KNOWN_ROOT_IPS` and windows into a config file.
5. **Additional parsers** — auth (sudo/su), syslog, then Docker / web.
6. **Multi-host correlation** — host tagging and cross-host detection.
7. **Stateful / streaming engine** — sliding windows, event expiry, bounded memory (Phase 9).
8. **Testing** — unit tests per parser and detector; a labelled benchmark dataset with precision/recall.
9. **Alert delivery** — Discord/Telegram/Slack/Email/webhooks with rate limiting.
10. **Hardening** — validate against log-injection, handle malformed/hostile log lines safely, and document trust boundaries.

Until these land, treat this project as an **educational SIEM foundation for homelab use**, not a production detection system.

---

*Reviewed alongside `ARCHITECTURE.md` and `DOCUMENTATION.md`. Assumptions here reflect the state at current `HEAD`.*
