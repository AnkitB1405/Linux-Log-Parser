from detectors.bruteforce import within


def detect_service_anomaly(events):

    # service -> [(timestamp, event_id), ...]
    service_events = {}
    alerts = []

    for event in events:

        if event["event_type"] not in [
            "service_started",
            "service_stopped"
        ]:
            continue

        service_events.setdefault(event["log_source"], []).append(
            (event["timestamp"], event["id"])
        )

    for service, entries in service_events.items():
        entries.sort()
        # Densest window anywhere, not just the last one — see the note in
        # detectors/bruteforce.py:within(). A restart storm in the morning is
        # invisible to a window anchored on the evening's last event.
        recent = within(entries, 300)

        if len(recent) >= 5:
            alerts.append({
                "severity": "high",
                "alert_type": "service_instability",
                "service": service,
                "events": len(recent),
                "timestamp": recent[-1][0],
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "investigate service immediately"
            })

        elif len(recent) >= 3:
            alerts.append({
                "severity": "medium",
                "alert_type": "service_instability",
                "service": service,
                "events": len(recent),
                "timestamp": recent[-1][0],
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "monitor service"
            })

    return alerts
