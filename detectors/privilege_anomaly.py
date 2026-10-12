"""
Attacks that show up in auth.log rather than in a login log.

SSH tells you who got in. auth.log tells you what happened next — and the
"next" is where an intrusion becomes persistent. Five findings:

  credential_spray        many accounts tried from one source
  backdoor_account        an account created and then privileged
  privileged_group_change an existing account gaining root-equivalent rights
  privilege_recon         somebody probing what sudo will let them do
  sensitive_command       sudo used to read the credential store

Nothing here looks at a single line in isolation except `sensitive_command`.
The rest are patterns across events, because a single `sudo` or a single failed
password is a Tuesday.
"""

SPRAY_WINDOW = 300
RECON_WINDOW = 600
CHAIN_WINDOW = 1800

# Membership in any of these is root, or one command away from it. `docker` is
# included deliberately: anyone who can talk to the Docker socket can start a
# privileged container and mount the host filesystem.
PRIVILEGED_GROUPS = {
    "sudo", "wheel", "admin", "adm", "root", "docker",
    "lxd", "disk", "shadow", "sudoers",
}

# Reading any of these is reading credentials, not administering a machine.
SENSITIVE_PATHS = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/passwd",
    "authorized_keys", "id_rsa", "id_ed25519", "/root/.ssh",
    "/etc/ssh/ssh_host", ".aws/credentials", ".kube/config",
)

# One account guessed many times is brute force; many accounts guessed once
# each is spraying. The discriminator is distinct usernames, not volume —
# which is why this cannot simply be bruteforce.py's job: that one keys on
# source IP and counts attempts.
SPRAY_MIN_USERS = 8

RECON_BANDS = [
    (5, "high", "block the account and check what it was probing for"),
    (3, "medium", "confirm who was testing their privileges"),
]


def detect_privilege_anomaly(events):

    failures = {}       # ip -> [(timestamp, event_id, username), ...]
    recon = {}          # username -> [(timestamp, event_id), ...]
    created = {}        # account -> (timestamp, event_id)
    privileged = []     # (timestamp, event_id, account, group)
    alerts = []

    for event in events:

        if event["log_source"] != LOG_SOURCE:
            continue

        entry = (event["timestamp"], event["id"])
        details = event["details"]
        event_type = event["event_type"]

        if event_type in ("service_auth_failure", "service_user_unknown"):
            ip = event["source_ip"]
            if ip:
                failures.setdefault(ip, []).append(entry + (event["username"],))

        elif event_type in ("sudo_denied", "sudo_auth_failure"):
            if event["username"]:
                recon.setdefault(event["username"], []).append(entry)

        elif event_type == "account_created":
            created.setdefault(details.get("target_user"), entry)

        elif event_type == "group_membership_added":
            if details.get("group") in PRIVILEGED_GROUPS:
                privileged.append(entry + (details.get("target_user"),
                                           details.get("group")))

        elif event_type == "sudo_command":
            command = details.get("command") or ""
            hit = next((p for p in SENSITIVE_PATHS if p in command), None)

            if hit:
                alerts.append({
                    "severity": "high",
                    "alert_type": "sensitive_command",
                    "service": LOG_SOURCE,
                    "username": event["username"],
                    "target": details.get("target_user"),
                    "path": hit,
                    "command": command,
                    "timestamp": event["timestamp"],
                    "event_ids": [event["id"]],
                    "recommended_action":
                    "confirm this read was authorised; treat the credentials as exposed",
                })

    # --- spraying: many accounts, one source --------------------------------

    for ip, entries in failures.items():
        entries.sort()
        window = densest(entries, SPRAY_WINDOW)
        users = {u for _, _, u in window if u}

        if len(users) >= SPRAY_MIN_USERS:
            alerts.append({
                "severity": "high",
                "alert_type": "credential_spray",
                "service": LOG_SOURCE,
                "source_ip": ip,
                "accounts_tried": len(users),
                "attempts": len(window),
                "timestamp": window[-1][0],
                "event_ids": [e[1] for e in window],
                "recommended_action":
                "block_ip — one source guessing many accounts is enumeration, "
                "not a user mistyping",
            })

    # --- the persistence chain ----------------------------------------------
    # An account created and then handed root is the quietest way to keep
    # access. Reported instead of privileged_group_change for that account,
    # not alongside it — one fact, one alert.

    chained = set()

    for timestamp, event_id, account, group in privileged:

        birth = created.get(account)

        if birth and 0 <= (timestamp - birth[0]).total_seconds() <= CHAIN_WINDOW:
            chained.add(account)
            alerts.append({
                "severity": "high",
                "alert_type": "backdoor_account",
                "service": LOG_SOURCE,
                "username": account,
                "group": group,
                "seconds_after_creation": int((timestamp - birth[0]).total_seconds()),
                "timestamp": timestamp,
                "event_ids": [birth[1], event_id],
                "recommended_action":
                "disable the account and audit what it did before removing it",
            })

    for timestamp, event_id, account, group in privileged:

        if account in chained:
            continue

        alerts.append({
            "severity": "high",
            "alert_type": "privileged_group_change",
            "service": LOG_SOURCE,
            "username": account,
            "group": group,
            "timestamp": timestamp,
            "event_ids": [event_id],
            "recommended_action":
            f"confirm this account was meant to be in '{group}'",
        })

    # --- privilege probing ---------------------------------------------------

    for username, entries in recon.items():
        entries.sort()
        window = densest(entries, RECON_WINDOW)
        severity, action = band(RECON_BANDS, len(window))

        if severity:
            alerts.append({
                "severity": severity,
                "alert_type": "privilege_recon",
                "service": LOG_SOURCE,
                "username": username,
                "attempts": len(window),
                "timestamp": window[-1][0],
                "event_ids": [e[1] for e in window],
                "recommended_action": action,
            })

    return alerts


LOG_SOURCE = "auth"


def densest(entries, seconds):
    """
    The densest run inside any `seconds` window, anywhere in the list.

    Same two-pointer scan as bruteforce.within() — anchoring on the last entry
    would only ever examine the tail of the log, which is how a 286-event
    attack went undetected against the AIT dataset.
    """

    best = []
    start = 0

    for end in range(len(entries)):
        while (entries[end][0] - entries[start][0]).total_seconds() > seconds:
            start += 1

        if end - start + 1 > len(best):
            best = entries[start:end + 1]

    return best


def band(bands, count):
    for threshold, severity, action in bands:
        if count >= threshold:
            return severity, action

    return None, None
