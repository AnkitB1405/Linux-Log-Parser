# Per-IP failed-login activity across sliding windows, to surface distributed
# or patterned attackers. Bands are ordered high-first and chained, so exactly
# one fires — previously both were plain `if`s, so an IP with 4+ suspicious
# windows raised a medium *and* a high for the same evidence.
WINDOW_SECONDS = 1800
BURST = 3

BANDS = [
    (4, "high", "investigate immediately"),
    (2, "medium", "monitor activity"),
]


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

        suspicious_windows = count_bursts(entries)
        severity, action = severity_for(suspicious_windows)

        if severity is None:
            continue

        alerts.append({
            "severity": severity,
            "alert_type": "behavior_anomaly",
            "service": log_sources[ip],
            "source_ip": ip,
            "windows": suspicious_windows,
            "timestamp": entries[-1][0],
            "event_ids": [e[1] for e in entries],
            "recommended_action": action
        })

    return alerts


def count_bursts(entries):
    """
    How many windows starting at an entry hold at least BURST attempts.

    ponytail: O(n^2) over one IP's failed logins. Fine at this volume; if a
    single IP ever produces tens of thousands, walk it with two indices.
    """

    windows = 0

    for i in range(len(entries)):
        count = 1

        for j in range(i + 1, len(entries)):
            if (entries[j][0] - entries[i][0]).total_seconds() <= WINDOW_SECONDS:
                count += 1
            else:
                break

        if count >= BURST:
            windows += 1

    return windows


def severity_for(count):
    """First band whose threshold is met. (None, None) below the lowest."""

    for threshold, severity, action in BANDS:
        if count >= threshold:
            return severity, action

    return None, None
