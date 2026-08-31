"""
Regression check for the detection engine.

Pins the alert set produced by sample_logs/ssh_dataset_v1.txt, which was
verified by hand against the 11 scenarios in that file (11/11 detected,
0 false positives). Any change to a parser, a threshold or a time window
that moves this set is a behaviour change and should be deliberate.

Run from the repo root:  python3 test_detectors.py
"""

import os
from datetime import datetime

from parser.ssh_parser import identify_event, set_reference_time, _parse_bsd
from parser.docker_parser import identify_event as identify_docker_event
from detectors.container_anomaly import detect_container_anomaly
from detectors.container_escape import detect_container_escape, assess
from detectors.registry import run_detectors

DATASET = "sample_logs/ssh_dataset_v1.txt"
DOCKER_DATASET = "sample_logs/docker_events_v1.jsonl"

# Captured from a real homelab `docker events` run. Service names and build
# labels are redacted; every event shape, sequence and command is untouched.
EXPECTED_DOCKER_EVENTS = 84

# (severity, container, command) — health-check execs must NOT appear here.
EXPECTED_CONTAINER_ALERTS = [
    ("high", "lp-web", "sh -c cat /etc/passwd"),
    ("medium", "lp-web", "ls /"),
]

# (alert_type, entity, severity) — entity is the source_ip, username or
# service the alert is about, whichever the detector keys on.
EXPECTED_ALERTS = [
    ("behavior_anomaly", "192.0.2.20", "medium"),
    ("behavior_anomaly", "198.51.100.55", "high"),
    ("behavior_anomaly", "203.0.113.40", "medium"),
    ("bruteforce", "198.51.100.10", "medium"),
    ("bruteforce", "198.51.100.11", "medium"),
    ("bruteforce", "203.0.113.40", "medium"),
    ("bruteforce", "203.0.113.90", "medium"),
    ("credential_compromise", "192.0.2.20", "medium"),
    ("root_bruteforce", "203.0.113.40", "high"),
    ("service_instability", "ssh", "high"),
    ("short_session", "engineer", "medium"),
    ("short_session", "user01", "medium"),
    ("short_session", "user02", "medium"),
    ("short_session", "user03", "medium"),
    ("slow_bruteforce", "192.0.2.20", "medium"),
    ("unauthorized_auth_method", "192.0.2.25", "high"),
    ("unauthorized_auth_method", "192.0.2.91", "high"),
    ("container_exec", "lp-web", "high"),
    ("container_exec", "lp-web", "medium"),
]

EXPECTED_EVENT_TYPES = {
    "service_started": 7,
    "invalid_user": 3,
    "failed_login": 26,
    "multiple_auth_failures": 4,
    "successful_login": 7,
    "session_opened": 7,
    "connection_closed": 4,
    "service_stopped": 6,
    "container_created": 7,
    "container_started": 10,
    "container_stopped": 5,
    "container_restarted": 3,
    "container_killed": 5,
    "container_died": 10,
    "container_destroyed": 7,
    "container_attached": 5,
    "container_exec_created": 4,
    "container_exec_started": 4,
    "container_exec_died": 4,
    "network_connected": 10,
    "network_disconnected": 10,
}


def build_events():
    """Both sources merged, mirroring what main.py actually runs."""

    events, errors = [], []

    # Anchor year-less timestamps to the fixture's mtime, exactly as main.py
    # does — a test that reads the input differently from the pipeline stops
    # testing the pipeline.
    set_reference_time(datetime.fromtimestamp(os.path.getmtime(DATASET)))

    for path, parse in ((DATASET, identify_event),
                        (DOCKER_DATASET, identify_docker_event)):
        with open(path) as file:
            for line in file:
                try:
                    event = parse(line)
                    if event:
                        events.append(event)
                except Exception as e:
                    errors.append((line.strip(), str(e)))

    return events, errors


def entity(alert):
    return (alert.get("source_ip") or alert.get("username")
            or alert.get("container") or alert.get("service"))


def check_timestamps():
    """
    Year-less BSD timestamps must resolve to a real year, and a December ->
    January span must not go backwards. Before the fix every event landed in
    1900 and that span produced a delta of about minus 365 days, which
    silently stopped every time-window detector from firing.
    """

    original = datetime.now()

    try:
        set_reference_time(datetime(2027, 1, 3, 9, 0))
        december = _parse_bsd("Dec 31 23:58:00")
        january = _parse_bsd("Jan  1 00:02:00")

        assert december.year == 2026, december
        assert january.year == 2027, january
        assert (january - december).total_seconds() == 240, "Dec->Jan went backwards"
    finally:
        set_reference_time(original)

    print("OK  year-less timestamps resolve, Dec->Jan span stays positive")


def check_escape_assessment():
    """
    The escape assessment, against the two HostConfig shapes captured from the
    homelab plus the real bind layouts of its running containers.

    These are configs, not events — the collector is what will attach them, so
    until it exists this pins the judgement rather than the pipeline.
    """

    captured_privileged = {
        "Privileged": True, "PidMode": "host", "NetworkMode": "bridge",
        "IpcMode": "private", "SecurityOpt": ["label=disable"], "CapAdd": None,
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/:/host:ro"],
    }
    captured_safe = {
        "Privileged": False, "PidMode": "", "NetworkMode": "bridge",
        "IpcMode": "private", "SecurityOpt": None, "CapAdd": None, "Binds": None,
    }

    assert assess(captured_privileged) == {
        "privileged", "pid_host", "docker_socket", "security_disabled"}
    assert assess(captured_safe) == set()

    # Real homelab bind layouts: ordinary data volumes must stay silent, or
    # the detector alerts on six of ten containers and gets switched off.
    quiet = [
        ["/docker/n8n:/home/node/.n8n"],
        ["/nas/photos:/usr/src/app/upload", "/etc/localtime:/etc/localtime:ro"],
        ["immich_model-cache:/cache"],
        ["/docker/openwebui:/app/backend/data"],
    ]
    for binds in quiet:
        assert assess({"Binds": binds}) == set(), binds

    # ...but the genuinely dangerous ones must not be
    assert assess({"Binds": ["/etc:/host-etc"]}) == {"sensitive_mount:/etc"}
    assert assess({"Binds": ["/:/host"]}) == {"sensitive_mount:/"}
    assert assess({"Binds": ["/etc:/host-etc:ro"]}) == set(), "ro mount should not raise"
    assert assess({"CapAdd": ["SYS_ADMIN"]}) == {"cap_sys_admin"}

    print("OK  escape assessment: 4 findings on the captured privileged config, "
          "0 on every real data-volume layout")


def check_docker():
    """The Docker path: JSON in, normalized events out, probes suppressed."""

    with open(DOCKER_DATASET) as file:
        events = [e for e in (identify_docker_event(l) for l in file) if e]

    assert len(events) == EXPECTED_DOCKER_EVENTS, (
        f"docker event count changed: {len(events)}")

    for event in events:
        assert event["log_source"] == "docker", event
        # Docker events carry no user or address; inventing either would be
        # worse than leaving them empty.
        assert event["username"] is None and event["source_ip"] is None, event
        # real epoch timestamps, unlike the BSD syslog path
        assert event["timestamp"].year > 2000, event

    # the attribute allowlist must hold: no compose/OCI build metadata leaks
    for event in events:
        leaked = [k for k in event["details"] if k.startswith(("com.docker", "org.opencontainers"))]
        assert not leaked, f"build metadata leaked into details: {leaked}"

    alerts = detect_container_anomaly(events)
    got = sorted((a["severity"], a["container"], a["command"]) for a in alerts)
    assert got == sorted(EXPECTED_CONTAINER_ALERTS), (
        f"container alert set changed\n  got: {got}")

    # Un-enriched events must produce NO escape alerts. `docker events`
    # carries none of these fields, and silence is the correct answer to
    # missing evidence — not an assumption that the container was safe.
    assert detect_container_escape(events) == [], (
        "escape detector fired without HostConfig enrichment")

    check_escape_assessment()

    # the probes must be seen and rejected, not simply absent
    execs = [e for e in events if e["event_type"] == "container_exec_created"]
    assert len(execs) > len(alerts), "no health-check exec in the fixture to suppress"
    print(f"OK  {len(events)} docker events, {len(alerts)} container alerts, "
          f"{len(execs) - len(alerts)} health-check execs suppressed")


def main():
    events, errors = build_events()

    assert not errors, f"parser errors on a known-good dataset: {errors}"

    # --- event shape: every parser routes through create_event ---
    required = {
        "id", "timestamp", "log_source", "host",
        "event_type", "severity", "username", "source_ip", "details",
    }
    for event in events:
        missing = required - set(event)
        assert not missing, f"{event['event_type']} missing {missing}"
        assert event["log_source"] in ("ssh", "docker"), event

    ids = [e["id"] for e in events]
    assert len(set(ids)) == len(ids), "event ids are not unique"

    counts = {}
    for event in events:
        counts[event["event_type"]] = counts.get(event["event_type"], 0) + 1
    assert counts == EXPECTED_EVENT_TYPES, f"event mix changed: {counts}"

    # --- detections ---
    alerts = run_detectors(events)
    got = sorted((a["alert_type"], entity(a), a["severity"]) for a in alerts)
    assert got == sorted(EXPECTED_ALERTS), (
        "alert set changed\n"
        f"  unexpected: {sorted(set(got) - set(EXPECTED_ALERTS))}\n"
        f"  missing:    {sorted(set(EXPECTED_ALERTS) - set(got))}"
    )

    # --- every alert is anchored in time and in evidence ---
    by_id = {e["id"]: e for e in events}
    for alert in alerts:
        assert alert.get("timestamp") is not None, f"no timestamp: {alert}"
        assert alert.get("event_ids"), f"no event_ids: {alert}"

        sources = [by_id[i] for i in alert["event_ids"]]
        assert all(i in by_id for i in alert["event_ids"]), f"dangling id: {alert}"
        # an alert must not claim to have fired before its own evidence
        assert alert["timestamp"] >= max(e["timestamp"] for e in sources), (
            f"alert predates its evidence: {alert}"
        )

    print(f"OK  {len(events)} events, {len(alerts)} alerts, {len(errors)} errors")
    print(f"OK  event shape normalized via create_event()")
    print(f"OK  all {len(alerts)} alerts carry timestamp + event_ids")

    check_timestamps()
    check_docker()


if __name__ == "__main__":
    main()
