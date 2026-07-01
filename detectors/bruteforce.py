from datetime import timedelta

def detect_bruteforce(events):

    failed_attempts = {}
    pam_attempts = {}

    alerts = []

    for event in events:
        ip = event.get("source_ip")

        if not ip:
            continue

        timestamp = event["timestamp"]
        if event["event_type"] == "failed_login":

            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(timestamp)

        elif event["event_type"] == "authentication_failure":

            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(timestamp)

        elif event["event_type"] == "multiple_auth_failures":

            if ip not in pam_attempts:
                pam_attempts[ip] = []

            pam_attempts[ip].append(timestamp)

    # PAM detections

    for ip, times in pam_attempts.items():

        if len(times) == 1:

            alerts.append({
                "severity": "medium",
                "alert_type": "bruteforce",
                "source_ip": ip,
                "pam_signals": 1,
                "recommended_action": "monitor"
            })

        elif len(times) >= 2:
            latest = times[-1]
            previous = times[-2]
            delta = latest - previous

            if delta.total_seconds() <= 180:
                alerts.append({
                    "severity": "high",
                    "alert_type": "bruteforce",
                    "source_ip": ip,
                    "pam_signals": len(times),
                    "recommended_action": "block_ip and report"
                })

    # Slow bruteforce detection

    for ip, times in failed_attempts.items():
        latest = max(times)
        recent_attempts = 0

        for t in times:

            delta = latest - t

            if delta.total_seconds() <= 600:

                recent_attempts += 1

        if 5 <= recent_attempts < 8:

            alerts.append({
                "severity": "medium",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": recent_attempts,
                "recommended_action": "monitor"
            })


        elif recent_attempts >= 8:

            alerts.append({
                "severity": "high",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": recent_attempts,
                "recommended_action": "block_ip and report"
            })

    return alerts