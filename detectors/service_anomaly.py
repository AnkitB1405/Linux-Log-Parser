def detect_service_anomaly(events):
    service_events = {}
    alerts = []

    for event in events:

        if event["event_type"] not in [
            "service_started",
            "service_stopped"
        ]:
            continue

        service = event["service"]
        timestamp = event["timestamp"]

        if service not in service_events:
            service_events[service] = []

        service_events[service].append(timestamp)

    for service, times in service_events.items():
        times.sort()
        latest = max(times)
        recent = 0

        for t in times:
            delta = latest - t

            if delta.total_seconds() <= 300:
                recent += 1

        if recent >= 5:
            alerts.append({
                "severity": "high",
                "alert_type": "service_instability",
                "service": service,
                "events": recent,
                "recommended_action":
                "investigate service immediately"
            })


        elif recent >= 3:
            alerts.append({
                "severity": "medium",
                "alert_type": "service_instability",
                "service": service,
                "events": recent,
                "recommended_action":
                "monitor service"
            })

    return alerts