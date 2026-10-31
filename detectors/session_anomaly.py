"""
Sessions that open and close within seconds.

The shape worth catching is a login that succeeds and then leaves almost
immediately — someone confirming a credential works, or an automated check
against a stolen account.

WHAT REAL DATA DID TO THE FIRST VERSION

It emitted 318,116 alerts in one run against 778,000 lines of real production
auth.log — 98.5% of everything the engine said, all of it wrong. Three separate
causes, each fixed below:

1. A session_opened was never consumed. The code read `sessions[username][-1]`
   and left it there, so ONE root login paired with EVERY subsequent
   connection_closed for root. That server had 479,350 root close events.

2. A connection_closed from a *failed* login is not the close of a session.
   Failed attempts produce closes without ever opening a session, and matching
   on username alone cannot tell the two apart.

3. One alert per pair rather than one per account. Even correct, that is the
   wrong granularity — brute force against one account is one finding.

Matching on username is still the weak point: the right key is the sshd
process id, which the envelope currently discards.
"""

WINDOW_SECONDS = 20


def detect_session_anomaly(events):

    # username -> [(timestamp, event_id), ...] of sessions still open
    open_sessions = {}

    # username -> [(duration, opened_id, closed_id, timestamp), ...]
    short = {}

    alerts = []

    for event in events:

        username = event["username"]

        if not username:
            continue

        if event["event_type"] == "session_opened":

            open_sessions.setdefault(username, []).append(
                (event["timestamp"], event["id"])
            )

        elif event["event_type"] in ("connection_closed", "session_closed"):

            waiting = open_sessions.get(username)

            if not waiting:
                # A close with nothing open. On a host under brute force this
                # is the overwhelming majority of closes, and pairing it with a
                # stale session is what produced the alert flood.
                continue

            opened_at, opened_id = waiting.pop()
            duration = (event["timestamp"] - opened_at).total_seconds()

            if 0 <= duration <= WINDOW_SECONDS:
                short.setdefault(username, []).append(
                    (duration, opened_id, event["id"], event["timestamp"])
                )

    # One alert per account, not per session. The count is the finding.
    for username, sessions in short.items():
        sessions.sort()
        evidence = [i for _d, opened, closed, _t in sessions
                    for i in (opened, closed)]

        alerts.append({
            "severity": "medium",
            "alert_type": "short_session",
            "service": "ssh",
            "username": username,
            "sessions": len(sessions),
            "duration": sessions[0][0],
            "timestamp": max(s[3] for s in sessions),
            "event_ids": evidence[:200],
            "recommended_action":
            "verify these logins were expected" if len(sessions) == 1 else
            f"{len(sessions)} sessions under {WINDOW_SECONDS}s for one account "
            f"— confirm whether the credential is being tested",
        })

    return alerts
