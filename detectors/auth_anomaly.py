# Authentication methods these hosts are configured to accept.
#
# The homelab, the laptop and the Metasploitable VM all run password
# authentication only, deliberately — the password is a second factor against
# someone who has physical access to the machine.
#
# So a *successful* login by any other method is not a configuration detail,
# it means a credential exists that nobody installed on purpose. Writing a key
# into ~/.ssh/authorized_keys is the standard way an intruder keeps access
# after the original break-in, and it survives a password change.
SANCTIONED_AUTH_METHODS = {"password"}


def detect_auth_anomaly(events):

    alerts = []

    for event in events:

        if event["event_type"] != "successful_login":
            continue

        method = event["details"].get("auth_method")

        # No captured method means a parser gap, not an intrusion — don't
        # raise on the parser's own blind spot.
        if method is None or method in SANCTIONED_AUTH_METHODS:
            continue

        alerts.append({
            "severity": "high",
            "alert_type": "unauthorized_auth_method",
            "service": event["log_source"],
            "username": event["username"],
            "source_ip": event["source_ip"],
            "auth_method": method,
            "timestamp": event["timestamp"],
            "event_ids": [event["id"]],
            "recommended_action":
            "inspect authorized_keys for this user and revoke unknown keys"
        })

    return alerts
