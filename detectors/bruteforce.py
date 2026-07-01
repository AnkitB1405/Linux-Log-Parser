def detect_bruteforce(events):

    failed_attempts = {}
    pam_attempts = {}
    root_attempts = {}

    alerts = []

    KNOWN_ROOT_IPS = {
        "100.112.185.127",
        "100.89.181.9",
        "100.110.185.112"
    }

    for event in events:

        ip = event.get("source_ip")

        if not ip:
            continue

        timestamp = event["timestamp"]
        event_type = event["event_type"]


        # Failed Login

        if event_type == "failed_login":
            username = event["username"]

            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(timestamp)

            if username == "root":

                if ip not in root_attempts:
                    root_attempts[ip] = []

                root_attempts[ip].append(timestamp)


        # Authentication Failure

        elif event_type == "authentication_failure":

            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(timestamp)


        # Multiple Auth Failures

        elif event_type == "multiple_auth_failures":

            if ip not in pam_attempts:
                pam_attempts[ip] = []

            pam_attempts[ip].append(timestamp)


        # Successful Login

        elif event_type == "successful_login":
            username = event["username"]

            if username == "root":

                if ip not in KNOWN_ROOT_IPS:

                    alerts.append({
                        "severity": "monitor",
                        "alert_type": "unknown_root_login",
                        "source_ip": ip,
                        "recommended_action":
                        "verify source"
                    })


    # PAM

    for ip, times in pam_attempts.items():
        times.sort()

        if len(times) == 1:

            alerts.append({
                "severity": "medium",
                "alert_type": "bruteforce",
                "source_ip": ip,
                "recommended_action":
                "monitor"

            })


        elif len(times) >= 2:
            delta = times[-1] - times[-2]

            if delta.total_seconds() <= 180:

                alerts.append({
                    "severity": "high",
                    "alert_type": "bruteforce",
                    "source_ip": ip,
                    "recommended_action":
                    "block_ip and report"
                })


    # Root

    for ip, times in root_attempts.items():
        times.sort()
        latest = max(times)
        recent = 0

        for t in times:
            delta = latest - t

            if delta.total_seconds() <= 600:
                recent += 1

        if recent >= 1:

            alerts.append({
                "severity": "medium",
                "alert_type": "root_attack",
                "source_ip": ip,
                "attempts": recent,
                "recommended_action":
                "monitor"
            })

        if ip in pam_attempts:

            alerts.append({
                "severity": "high",
                "alert_type": "root_bruteforce",
                "source_ip": ip,
                "recommended_action":
                "block_ip and report"

            })


    # Slow brute force

    for ip, times in failed_attempts.items():
        times.sort()
        latest = max(times)
        recent = 0

        for t in times:
            delta = latest - t

            if delta.total_seconds() <= 600:
                recent += 1

        if 5 <= recent < 8:

            alerts.append({
                "severity": "medium",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": recent,
                "recommended_action":
                "monitor"

            })

        elif recent >= 8:

            alerts.append({
                "severity": "high",
                "alert_type": "slow_bruteforce",
                "source_ip": ip,
                "attempts": recent,
                "recommended_action":
                "block_ip and report"
            })

    return alerts