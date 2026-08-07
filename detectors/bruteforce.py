KNOWN_ROOT_IPS = {
    "100.112.185.127",
    "100.89.181.9",
    "100.110.185.112"
}


def detect_bruteforce(events):

    # each maps ip -> [(timestamp, event_id), ...]
    failed_attempts = {}
    pam_attempts = {}
    root_attempts = {}

    alerts = []

    for event in events:

        ip = event.get("source_ip")

        if not ip:
            continue

        entry = (event["timestamp"], event["id"])
        event_type = event["event_type"]

        # Failed Login

        if event_type == "failed_login":

            failed_attempts.setdefault(ip, []).append(entry)

            if event["username"] == "root":
                root_attempts.setdefault(ip, []).append(entry)

        # Authentication Failure

        elif event_type == "authentication_failure":

            failed_attempts.setdefault(ip, []).append(entry)

        # Multiple Auth Failures

        elif event_type == "multiple_auth_failures":

            pam_attempts.setdefault(ip, []).append(entry)

        # Successful Login

        elif event_type == "successful_login":

            if event["username"] == "root" and ip not in KNOWN_ROOT_IPS:

                alerts.append({
                    "severity": "monitor",
                    "alert_type": "unknown_root_login",
                    "source_ip": ip,
                    "timestamp": event["timestamp"],
                    "event_ids": [event["id"]],
                    "recommended_action":
                    "verify source"
                })

    # PAM

    for ip, entries in pam_attempts.items():
        entries.sort()

        if len(entries) == 1:

            alerts.append({
                "severity": "medium",
                "alert_type": "bruteforce",
                "source_ip": ip,
                "timestamp": entries[-1][0],
                "event_ids": [e[1] for e in entries],
                "recommended_action":
                "monitor"
            })

        elif len(entries) >= 2:
            delta = entries[-1][0] - entries[-2][0]

            if delta.total_seconds() <= 180:

                alerts.append({
                    "severity": "high",
                    "alert_type": "bruteforce",
                    "source_ip": ip,
                    "timestamp": entries[-1][0],
                    "event_ids": [e[1] for e in entries],
                    "recommended_action":
                    "block_ip and report"
                })

    # Root

    for ip, entries in root_attempts.items():
        entries.sort()
        latest = entries[-1][0]
        recent = [e for e in entries if (latest - e[0]).total_seconds() <= 600]

        if len(recent) >= 1:

            alerts.append({
                "severity": "medium",
                "alert_type": "root_attack",
                "source_ip": ip,
                "attempts": len(recent),
                "timestamp": latest,
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "monitor"
            })

        if ip in pam_attempts:

            correlated = recent + pam_attempts[ip]

            alerts.append({
                "severity": "high",
                "alert_type": "root_bruteforce",
                "source_ip": ip,
                "timestamp": max(e[0] for e in correlated),
                "event_ids": [e[1] for e in correlated],
                "recommended_action":
                "block_ip and report"
            })

    # Slow brute force

    for ip, entries in failed_attempts.items():
        entries.sort()
        latest = entries[-1][0]
        recent = [e for e in entries if (latest - e[0]).total_seconds() <= 600]

        if 5 <= len(recent) < 8:

            alerts.append({
                "severity": "medium",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": len(recent),
                "timestamp": latest,
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "monitor"
            })

        elif len(recent) >= 8:

            alerts.append({
                "severity": "high",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": len(recent),
                "timestamp": latest,
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "block_ip and report"
            })

    return alerts
