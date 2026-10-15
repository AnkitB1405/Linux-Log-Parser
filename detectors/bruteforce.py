# Homelab addresses that legitimately log in as root. Tailnet peers — the
# planned trust-tier work generalises this from three literals to a rule.
KNOWN_ROOT_IPS = {
    "100.112.185.127",
    "100.89.181.9",
    "100.110.185.112",
}

PAM_WINDOW = 180
ROOT_WINDOW = 600
SLOW_WINDOW = 600

# Root targeting needs a real attempt count. This previously read `>= 1`,
# which can never be false — `recent` is filtered against `latest`, and
# `latest - latest` is always 0 — so every single failed root login raised an
# alert.
ROOT_MIN = 3

# Any credential rejection, whatever service rejected it. A dovecot, exim or
# vsftpd failure is the same signal as an sshd one, and this detector is
# source-agnostic by design — keying only on the SSH event type made it blind
# to every other service in auth.log.
#
# Found by the AIT run: 286 labelled brute-force attempts against one account,
# all parsed correctly into events, produced no alert at all, because the
# parser emits `service_auth_failure` and this detector only knew
# `authentication_failure`.
FAILURE_EVENTS = {
    "failed_login",
    "authentication_failure",
    "service_auth_failure",
}

SLOW_BANDS = [
    (8, "high", "block_ip and report"),
    (5, "medium", "monitor"),
]


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

        if event_type in FAILURE_EVENTS:

            failed_attempts.setdefault(ip, []).append(entry)

            if event["username"] == "root":
                root_attempts.setdefault(ip, []).append(entry)

        elif event_type == "multiple_auth_failures":

            pam_attempts.setdefault(ip, []).append(entry)

        elif event_type == "successful_login":

            if event["username"] == "root" and ip not in KNOWN_ROOT_IPS:

                alerts.append(build(
                    "monitor", "unknown_root_login", ip, [entry],
                    "verify source"))

    # PAM signals

    for ip, entries in pam_attempts.items():
        entries.sort()

        if len(entries) >= 2 and delta(entries) <= PAM_WINDOW:
            alerts.append(build(
                "high", "bruteforce", ip, entries, "block_ip and report"))
        else:
            alerts.append(build(
                "medium", "bruteforce", ip, entries, "monitor"))

    # Root targeting. These are two bands of one finding, not two findings —
    # ordered so exactly one fires, or the same evidence raises both.

    for ip, entries in root_attempts.items():
        entries.sort()
        recent = within(entries, ROOT_WINDOW)

        if len(recent) < ROOT_MIN:
            continue

        if ip in pam_attempts:
            alerts.append(build(
                "high", "root_bruteforce", ip, recent + pam_attempts[ip],
                "block_ip and report", attempts=len(recent)))
        else:
            alerts.append(build(
                "medium", "root_attack", ip, recent,
                "monitor", attempts=len(recent)))

    # Slow brute force — volume from one address, whoever it targets

    for ip, entries in failed_attempts.items():
        entries.sort()
        recent = within(entries, SLOW_WINDOW)
        severity, action = band(SLOW_BANDS, len(recent))

        if severity:
            alerts.append(build(
                severity, "slow_bruteforce", ip, recent, action,
                attempts=len(recent)))

    return alerts


def build(severity, alert_type, ip, entries, action, **extra):
    """One alert shape. Timestamp and evidence always come from the events."""

    return {
        "severity": severity,
        "alert_type": alert_type,
        "source_ip": ip,
        "timestamp": max(e[0] for e in entries),
        "event_ids": [e[1] for e in entries],
        "recommended_action": action,
        **extra,
    }


def within(entries, seconds):
    """
    The densest run of entries inside any `seconds` window, anywhere in the
    list. `entries` must be sorted.

    This previously anchored on the most recent entry, which meant only the
    tail of the log was ever examined. Measured against the AIT Log Data Set:
    a labelled hydra attack of 286 authentication failures in 222 seconds went
    completely undetected, because the last failure in the file was 24 hours
    later and the 600-second window from there excluded the entire burst.

    Batch analysis has to look everywhere, not just at the end. Two pointers,
    so this stays linear.
    """

    best = []
    start = 0

    for end in range(len(entries)):
        while (entries[end][0] - entries[start][0]).total_seconds() > seconds:
            start += 1

        if end - start + 1 > len(best):
            best = entries[start:end + 1]

    return best


def delta(entries):
    """Seconds between the last two entries."""

    return (entries[-1][0] - entries[-2][0]).total_seconds()


def band(bands, count):
    """First band whose threshold is met. (None, None) below the lowest."""

    for threshold, severity, action in bands:
        if count >= threshold:
            return severity, action

    return None, None
