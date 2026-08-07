def detect_behavior(events):

    # ip -> [(timestamp, event_id), ...]
    login_history = {}
    log_sources = {}
    alerts = []

    for event in events:

        if event["event_type"] != "failed_login":
            continue

        ip = event["source_ip"]

        login_history.setdefault(ip, []).append(
            (event["timestamp"], event["id"])
        )
        log_sources[ip] = event["log_source"]

    for ip, entries in login_history.items():
        entries.sort()
        suspicious_windows = 0

        for i in range(len(entries)):
            count = 1

            for j in range(i + 1, len(entries)):
                delta = entries[j][0] - entries[i][0]

                if delta.total_seconds() <= 1800:
                    count += 1

                else:
                    break

            if count >= 3:
                suspicious_windows += 1

        latest = entries[-1][0]
        event_ids = [e[1] for e in entries]

        if suspicious_windows >= 2:
            alerts.append({
                "severity": "medium",
                "alert_type": "behavior_anomaly",
                "service": log_sources[ip],
                "source_ip": ip,
                "windows": suspicious_windows,
                "timestamp": latest,
                "event_ids": event_ids,
                "recommended_action": "monitor activity"
            })

        if suspicious_windows >= 4:
            alerts.append({
                "severity": "high",
                "alert_type": "behavior_anomaly",
                "service": log_sources[ip],
                "source_ip": ip,
                "windows": suspicious_windows,
                "timestamp": latest,
                "event_ids": event_ids,
                "recommended_action": "investigate immediately"
            })

    return alerts
