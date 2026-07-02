from datetime import timedelta

def detect_behavior(events):
    login_history = {}
    alerts = []

    for event in events:

        if event["event_type"] != "failed_login":
            continue

        ip = event["source_ip"]
        timestamp = event["timestamp"]

        if ip not in login_history:
            login_history[ip] = []

        login_history[ip].append(timestamp)

    for ip, times in login_history.items():
        times.sort()
        suspicious_windows = 0

        for i in range(len(times)):
            count = 1

            for j in range(i + 1, len(times)):
                delta = times[j] - times[i]

                if delta.total_seconds() <= 1800:
                    count += 1

                else:
                    break

            if count >= 3:
                suspicious_windows += 1

        if suspicious_windows >= 2:
            alerts.append({
                "severity": "medium",
                "alert_type": "behavior_anomaly",
                "service": event.get("service"),
                "source_ip": ip,
                "windows": suspicious_windows,
                "recommended_action": "monitor activity"
            })

        if suspicious_windows >= 4:
            alerts.append({
                "severity": "high",
                "alert_type": "behavior_anomaly",
                "service": event.get("service"),
                "source_ip": ip,
                "windows": suspicious_windows,
                "recommended_action": "investigate immediately"
            })

    return alerts