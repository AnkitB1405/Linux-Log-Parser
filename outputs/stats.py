def generate_statistics(events, alerts):
    statistics = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "high_alerts": 0,
        "medium_alerts": 0,
        "services": {},
        "event_types": {}
    }

    for alert in alerts:
        severity = alert["severity"]

        if severity == "high":
            statistics["high_alerts"] += 1

        elif severity == "medium":
            statistics["medium_alerts"] += 1

    for event in events:
        service = event.get("service")
        event_type = event["event_type"]
        statistics["services"][service] = statistics["services"].get(service, 0) + 1
        statistics["event_types"][event_type] = statistics["event_types"].get(event_type, 0) + 1

    return statistics