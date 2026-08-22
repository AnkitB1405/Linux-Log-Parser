# Failed-login bursts followed by a success on the same (user, ip) inside the
# window. Bands are ordered high-first so they stay mutually exclusive — the
# previous order tested `>= 5` before `>= 8`, which made `high` unreachable.
WINDOW_SECONDS = 600

BANDS = [
    (8, "high", "investigate immediately"),
    (5, "medium", "verify login"),
]


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

            if key not in failed_attempts:
                continue

            timestamp = event["timestamp"]

            recent = [
                e for e in failed_attempts[key]
                if (timestamp - e[0]).total_seconds() <= WINDOW_SECONDS
            ]

            severity, action = severity_for(len(recent))

            if severity is None:
                continue

            alerts.append({
                "severity": severity,
                "alert_type": "credential_compromise",
                "service": event["log_source"],
                "username": event["username"],
                "source_ip": event["source_ip"],
                "failed_attempts": len(recent),
                "timestamp": timestamp,
                # the success itself is the moment of compromise, so it
                # anchors the alert and belongs in the evidence list
                "event_ids": [e[1] for e in recent] + [event["id"]],
                "recommended_action": action
            })

    return alerts


def severity_for(count):
    """First band whose threshold is met. (None, None) below the lowest."""

    for threshold, severity, action in BANDS:
        if count >= threshold:
            return severity, action

    return None, None
