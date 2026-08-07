def detect_credential_compromise(events):

    # (username, ip) -> [(timestamp, event_id), ...]
    failed_attempts = {}
    alerts = []

    for event in events:

        key = (event["username"], event["source_ip"])

        if event["event_type"] == "failed_login":

            failed_attempts.setdefault(key, []).append(
                (event["timestamp"], event["id"])
            )

        elif event["event_type"] == "successful_login":

            if key in failed_attempts:
                timestamp = event["timestamp"]

                recent = [
                    e for e in failed_attempts[key]
                    if (timestamp - e[0]).total_seconds() <= 600
                ]

                # the success itself is the moment of compromise, so it
                # anchors the alert and belongs in the evidence list
                event_ids = [e[1] for e in recent] + [event["id"]]

                if len(recent) >= 5:
                    alerts.append({
                        "severity": "medium",
                        "alert_type": "credential_compromise",
                        "service": event["log_source"],
                        "username": event["username"],
                        "source_ip": event["source_ip"],
                        "failed_attempts": len(recent),
                        "timestamp": timestamp,
                        "event_ids": event_ids,
                        "recommended_action": "verify login"
                    })

                elif len(recent) >= 8:

                    alerts.append({
                        "severity": "high",
                        "alert_type": "credential_compromise",
                        "service": event["log_source"],
                        "username": event["username"],
                        "source_ip": event["source_ip"],
                        "failed_attempts": len(recent),
                        "timestamp": timestamp,
                        "event_ids": event_ids,
                        "recommended_action": "investigate immediately"
                    })

    return alerts
