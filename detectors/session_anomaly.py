def detect_session_anomaly(events):

    sessions = {}
    alerts = []

    for event in events:

        if event["event_type"] == "session_opened":

            username = event["username"]
            timestamp = event["timestamp"]

            if username not in sessions:
                sessions[username] = []

            sessions[username].append(timestamp)

        elif event["event_type"] == "connection_closed":

            username = event["username"]
            timestamp = event["timestamp"]

            if username in sessions:
                latest = sessions[username][-1]
                delta = timestamp - latest

                if delta.total_seconds() <= 20:

                    alerts.append({
                        "severity": "medium",
                        "alert_type": "short_session",
                        "service": event.get("service"),
                        "username": username,
                        "duration": delta.total_seconds(),
                        "recommended_action": "monitor"
                    })

    return alerts