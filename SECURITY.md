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
| Unsanctioned authentication method | `auth_anomaly` | A **successful** login by any method outside `SANCTIONED_AUTH_METHODS` (`{"password"}`). These hosts never use key auth, so a publickey success means a key was installed that nobody sanctioned — a persistence indicator, not an intrusion attempt |
| Interactive access to a container | `container_anomaly` | `docker exec` into a running container, with liveness probes suppressed by command pattern |
| Container configured to reach the host | `container_escape` | `Privileged`, host pid/net/ipc namespaces, disabled confinement, dangerous capabilities, the Docker socket, or a read-write bind of a sensitive host path — minus what is already expected for that container |

**Out of scope (today):** kernel/network-level attacks, malware, data exfiltration, log tampering that removes lines, web and application logs, and any host the parser has no logs for.

**Partly in scope:** container escape *configuration* is assessed (`container_escape`), but only for events the collector has enriched with `docker inspect` output. Escape *behaviour* — what a container actually did with that access — is not observed at all.

**Adversary assumption:** an unauthenticated or low-privileged remote attacker probing SSH, or an attacker whose activity is visible in standard `sshd`/PAM/`dockerd` log output.

### Deployment context

The monitored services are **reachable only over the Tailscale tailnet**; none of the Docker workloads are published to the public internet, and SSH is not exposed on a public interface. That is a real and load-bearing mitigating control: the realistic Docker adversary is not an anonymous internet scanner but someone already inside the tailnet, or a compromised container reached through a vulnerability in a service the owner runs.

This changes the *likelihood* of the Docker threats above, not their *impact* — a container holding `/var/run/docker.sock` is still equivalent to root on the host once reached. Detection is therefore built to catch the post-compromise stage: a new container appearing with host access, an unexpected `docker exec`, a key installed for an authentication method that is never used. It is not a perimeter control and does not pretend to be one.

Note also that the tailnet is why `KNOWN_ROOT_IPS` contains `100.x` addresses: those are tailnet peers, and the planned trust-tier work generalises exactly this — `100.64.0.0/10` is the owner, LAN is probably the owner, anything else is not.

---

## Current Assumptions

- **Log integrity is trusted.** The engine assumes logs are complete and unmodified. An attacker who can edit or delete log lines can evade detection.
- **Timestamps are reliable and monotonic.** The Mint homelab — the always-on install — reads RFC3339 `auth.log` and carries a real year and UTC offset. The BSD path (journald short output, Metasploitable) still has no year in the line and lands in 1900, so cross-year and DST edge cases are undefined there. Docker events carry epoch timestamps and are unaffected.
- **Single host, multiple sources** per run. SSH and Docker are parsed into one event stream on one machine. There is no multi-*host* correlation: one copy of the project runs on each device and reads only that device's logs.
- **Two hardcoded allowlists are correctly maintained.** `KNOWN_ROOT_IPS` (`detectors/bruteforce.py`) and `ALLOWED` (`detectors/container_escape.py`); stale entries cause missed or false alerts in both directions. `ALLOWED` is keyed on container **name** rather than id, because compose recreates containers and ids change on every `up`.
- **Container configuration is only known if enriched.** `docker events` carries none of the escape-relevant fields — verified as zero occurrences across 84 captured events. `container_escape` skips un-enriched events rather than treating them as safe, so before the collector exists it reports nothing at all. Silence there means "not observed", never "clean".
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
