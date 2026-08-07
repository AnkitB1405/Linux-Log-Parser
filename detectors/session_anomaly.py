def detect_session_anomaly(events):

    # username -> [(timestamp, event_id), ...] of session_opened
    sessions = {}
    alerts = []

    for event in events:

        if event["event_type"] == "session_opened":

            sessions.setdefault(event["username"], []).append(
                (event["timestamp"], event["id"])
            )

        elif event["event_type"] == "connection_closed":

            username = event["username"]
            timestamp = event["timestamp"]

            if username in sessions:
                opened_at, opened_id = sessions[username][-1]
                delta = timestamp - opened_at

                if delta.total_seconds() <= 20:

                    alerts.append({
                        "severity": "medium",
                        "alert_type": "short_session",
                        "service": event["log_source"],
                        "username": username,
                        "duration": delta.total_seconds(),
                        "timestamp": timestamp,
                        "event_ids": [opened_id, event["id"]],
                        "recommended_action": "monitor"
                    })

    return alerts
