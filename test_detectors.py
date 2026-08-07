"""
Regression check for the detection engine.

Pins the alert set produced by sample_logs/ssh_dataset_v1.txt, which was
verified by hand against the 11 scenarios in that file (11/11 detected,
0 false positives). Any change to a parser, a threshold or a time window
that moves this set is a behaviour change and should be deliberate.

Run from the repo root:  python3 test_detectors.py
"""

from parser.ssh_parser import identify_event
from detectors.bruteforce import detect_bruteforce
from detectors.service_anomaly import detect_service_anomaly
from detectors.credential_compromise import detect_credential_compromise
from detectors.behavior import detect_behavior
from detectors.session_anomaly import detect_session_anomaly

DATASET = "sample_logs/ssh_dataset_v1.txt"

# (alert_type, entity, severity) — entity is the source_ip, username or
# service the alert is about, whichever the detector keys on.
EXPECTED_ALERTS = [
    ("behavior_anomaly", "192.0.2.20", "medium"),
    ("behavior_anomaly", "198.51.100.55", "high"),
    ("behavior_anomaly", "198.51.100.55", "medium"),
    ("behavior_anomaly", "203.0.113.40", "medium"),
    ("bruteforce", "198.51.100.10", "medium"),
    ("bruteforce", "198.51.100.11", "medium"),
    ("bruteforce", "203.0.113.40", "medium"),
    ("bruteforce", "203.0.113.90", "medium"),
    ("credential_compromise", "192.0.2.20", "medium"),
    ("root_attack", "203.0.113.40", "medium"),
    ("root_bruteforce", "203.0.113.40", "high"),
    ("service_instability", "ssh", "high"),
    ("short_session", "engineer", "medium"),
    ("short_session", "user01", "medium"),
    ("short_session", "user02", "medium"),
    ("short_session", "user03", "medium"),
    ("slow_bruteforce", "192.0.2.20", "medium"),
]

EXPECTED_EVENT_TYPES = {
    "service_started": 7,
    "invalid_user": 3,
    "failed_login": 26,
    "multiple_auth_failures": 4,
    "successful_login": 5,
    "session_opened": 7,
    "connection_closed": 4,
    "service_stopped": 6,
}


def build_events():
    events, errors = [], []

    with open(DATASET) as file:
        for line in file:
            try:
                event = identify_event(line)
                if event:
                    events.append(event)
            except Exception as e:
                errors.append((line.strip(), str(e)))

    return events, errors


def run_detectors(events):
    return (
        detect_bruteforce(events)
        + detect_service_anomaly(events)
        + detect_credential_compromise(events)
        + detect_behavior(events)
        + detect_session_anomaly(events)
    )


def entity(alert):
    return alert.get("source_ip") or alert.get("username") or alert.get("service")


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
        assert event["log_source"] == "ssh", event
        assert event["host"] == "Sentinel", event

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


if __name__ == "__main__":
    main()
