"""
Web attack patterns in Apache / Nginx access logs.

Three findings, all correlated per source address:

  scanning        someone enumerating paths that do not exist
  auth bruteforce repeated 401/403 against the same resource
  exploitation    repeated 5xx, i.e. requests the application could not survive

A single 404 is not an event worth anyone's attention — a missing favicon
produces one. Volume inside a window is the signal, which is why every rule
here is a count over time rather than a property of one request.
"""

SCAN_WINDOW = 60
AUTH_WINDOW = 300
ERROR_WINDOW = 300
COMPROMISE_WINDOW = 600

SCAN_BANDS = [
    (20, "high", "block_ip and review what was reachable"),
    (8, "medium", "monitor"),
]

AUTH_BANDS = [
    (10, "high", "block_ip and force a credential reset"),
    (5, "medium", "monitor"),
]

ERROR_MIN = 3


def detect_web_anomaly(events):

    not_found = {}        # ip -> [(timestamp, event_id), ...]
    auth_failures = {}    # (username-or-path, ip) -> [...]
    auth_by_ip = {}
    server_errors = {}
    scanners = {}         # ip -> the tool that named itself
    successes = {}        # ip -> [(timestamp, event_id), ...]

    alerts = []

    for event in events:

        if event["log_source"] != "web":
            continue

        ip = event["source_ip"]

        if not ip:
            continue

        entry = (event["timestamp"], event["id"])
        details = event["details"]
        event_type = event["event_type"]

        if details.get("scanner_agent"):
            scanners.setdefault(ip, details["scanner_agent"])

        if event_type == "http_not_found":
            not_found.setdefault(ip, []).append(entry)

        elif event_type == "http_auth_failure":
            auth_by_ip.setdefault(ip, []).append(entry)
            auth_failures.setdefault((details.get("path"), ip), []).append(entry)

        elif event_type == "http_server_error":
            server_errors.setdefault(ip, []).append(entry)

        elif event_type == "http_request":
            successes.setdefault(ip, []).append((entry, details.get("path")))

    # --- scanning -----------------------------------------------------------
    # A self-identifying tool is decisive on its own: nothing legitimate sends
    # "Nikto" as its user agent. Volume alone still counts, because a scanner
    # that changed its agent still generates the same 404 pattern.

    for ip in set(not_found) | set(scanners):
        entries = sorted(not_found.get(ip, []))
        recent = within(entries, SCAN_WINDOW) if entries else []
        tool = scanners.get(ip)
        severity, action = band(SCAN_BANDS, len(recent))

        if tool:
            severity = "high"
            action = f"block_ip — {tool} identified itself in the user agent"

        if not severity:
            continue

        alerts.append({
            "severity": severity,
            "alert_type": "web_scanning",
            "service": "web",
            "source_ip": ip,
            "not_found": len(recent),
            "scanner": tool,
            "timestamp": max(e[0] for e in recent) if recent else entries[-1][0],
            "event_ids": [e[1] for e in recent],
            "recommended_action": action,
        })

    # --- credential attack against a web resource ---------------------------

    for ip, entries in auth_by_ip.items():
        entries.sort()
        recent = within(entries, AUTH_WINDOW)
        severity, action = band(AUTH_BANDS, len(recent))

        if severity:
            alerts.append({
                "severity": severity,
                "alert_type": "web_auth_bruteforce",
                "service": "web",
                "source_ip": ip,
                "failures": len(recent),
                "timestamp": recent[-1][0],
                "event_ids": [e[1] for e in recent],
                "recommended_action": action,
            })

        # Failures followed by a success from the same address is the web
        # equivalent of credential_compromise — and the more urgent finding,
        # so it is reported regardless of whether the burst hit a band.
        latest = entries[-1][0]

        for (entry, path) in successes.get(ip, []):
            if 0 <= (entry[0] - latest).total_seconds() <= COMPROMISE_WINDOW:
                alerts.append({
                    "severity": "high",
                    "alert_type": "web_credential_compromise",
                    "service": "web",
                    "source_ip": ip,
                    "path": path,
                    "failures": len(entries),
                    "timestamp": entry[0],
                    "event_ids": [e[1] for e in entries] + [entry[1]],
                    "recommended_action": "verify this session and reset the credential",
                })
                break

    # --- application errors under repetition --------------------------------

    for ip, entries in server_errors.items():
        entries.sort()
        recent = within(entries, ERROR_WINDOW)

        if len(recent) >= ERROR_MIN:
            alerts.append({
                "severity": "medium",
                "alert_type": "web_server_errors",
                "service": "web",
                "source_ip": ip,
                "errors": len(recent),
                "timestamp": recent[-1][0],
                "event_ids": [e[1] for e in recent],
                "recommended_action":
                "repeated 5xx from one address — check whether input is breaking the app",
            })

    return alerts


def within(entries, seconds):
    latest = entries[-1][0]

    return [e for e in entries if (latest - e[0]).total_seconds() <= seconds]


def band(bands, count):
    for threshold, severity, action in bands:
        if count >= threshold:
            return severity, action

    return None, None
