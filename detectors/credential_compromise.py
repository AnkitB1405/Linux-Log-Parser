def detect_credential_compromise(events):
    failed_attempts = {}
    alerts = []

    for event in events:

        if event["event_type"] == "failed_login":
            username = event["username"]
            ip = event["source_ip"]
            timestamp = event["timestamp"]
            key = (username, ip)

            if key not in failed_attempts:
                failed_attempts[key] = []

            failed_attempts[key].append(timestamp)

        elif event["event_type"] == "successful_login":
            username = event["username"]
            ip = event["source_ip"]
            timestamp = event["timestamp"]
            key = (username, ip)

            if key in failed_attempts:
                recent = 0

                for t in failed_attempts[key]:
                    delta = timestamp - t

                    if delta.total_seconds() <= 600:
                        recent += 1

                if recent >= 5:
                    alerts.append({
                        "severity": "medium",
                        "alert_type": "credential_compromise",
                        "service": event.get("service"),
                        "username": username,
                        "source_ip": ip,
                        "failed_attempts": recent,
                        "recommended_action": "verify login"
                    })

                elif recent >= 8:

                    alerts.append({
                        "severity": "high",
                        "alert_type": "credential_compromise",
                        "service": event.get("service"),
                        "username": username,
                        "source_ip": ip,
                        "failed_attempts": recent,
                        "recommended_action": "investigate immediately"
                    })

    return alerts