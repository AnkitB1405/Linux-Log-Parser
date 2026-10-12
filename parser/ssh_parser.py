import re

from parser.envelope import key_values, parse_line, set_reference_time  # noqa: F401
from parser.event_schema import create_event

LOG_SOURCE = "ssh"

# --- Message patterns ------------------------------------------------------
#
# One row per event type; first match wins. Named groups `username` and
# `source_ip` are promoted onto the event, every other group lands in
# `details`. Adding an event type is adding a row, not editing control flow.
#
# Ordering is not load-bearing — each pattern is specific enough that it
# cannot claim another row's lines. Two rows may share an event_type when
# sshd spells the same event more than one way.

# Matches IPv4 and IPv6 alike, including the Tailscale ULAs
# (fd7a:115c:a1e0::b201:1f2c) the homelab logs are full of.
# Which processes this parser is entitled to speak for.
#
# /var/log/auth.log is NOT an SSH log — it is the authentication log, shared by
# cron, sudo, dovecot, su and anything else using PAM. Real AIT auth.log data
# is 910 CRON lines and 314 dovecot lines with no sshd at all, and without this
# check every one of them parsed "successfully" as an SSH event: cron jobs
# became SSH sessions and a mail-server brute force became SSH authentication
# failure. 100% coverage, 100% wrong.
#
# systemd is included because `Started ssh.service` is written by systemd, not
# by sshd; those two patterns are specific enough that no other unit matches.
SSH_PROCESSES = {"sshd", "sshd-session", "sshd-auth", "systemd"}

IP = r"[0-9a-fA-F.:]+"

# `Connection closed by ...` names the account three different ways, or not
# at all:  by root / by user root / by invalid user root / by authenticating
# user root.
_WHO = r"(?:(?:invalid |authenticating )?user )?"

SSH_PATTERNS = [
    # publickey is included because key auth is the normal login path on the
    # Mint homelab. Matching only `password` would make the parser blind to
    # every legitimate login there.
    ("successful_login", re.compile(
        r"Accepted (?P<auth_method>password|publickey) for (?P<username>\S+) "
        r"from (?P<source_ip>\S+)")),

    ("failed_login", re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) "
        r"from (?P<source_ip>\S+)")),

    ("invalid_user", re.compile(
        r"Invalid user (?:(?P<username>\S+) )?from (?P<source_ip>\S+)")),

    ("max_auth_attempts", re.compile(
        r"maximum authentication attempts exceeded for (?:invalid user )?"
        r"(?P<username>\S+) from (?P<source_ip>\S+)")),

    ("session_opened", re.compile(
        r"session opened for user (?P<username>[^(\s]+)\S* "
        r"by (?P<initiated_by>[^(\s]*)")),

    ("session_closed", re.compile(
        r"session closed for user (?P<username>\S+)")),

    # sshd says "Connection closed by" when it hangs up and "Disconnected
    # from" when the client does. Same event, two spellings.
    ("connection_closed", re.compile(
        r"Connection closed by " + _WHO +
        r"(?:(?P<username>\S+) )?(?P<source_ip>" + IP + r") port")),

    ("connection_closed", re.compile(
        r"Disconnected from " + _WHO +
        r"(?:(?P<username>\S+) )?(?P<source_ip>" + IP + r") port")),

    ("multiple_auth_failures", re.compile(
        r"PAM (?P<count>\d+) more authentication failures")),

    ("authentication_failure", re.compile(
        r"(?P<auth_module>\w+)\([^)]+\): authentication failure;")),

    ("user_unknown", re.compile(
        r"(?P<auth_module>\w+)\([^)]+\): check pass; user unknown")),

    # Pre-auth aborts: clients that never got as far as offering a credential.
    # Port scanners, non-SSH probes, and old clients whose key exchange is
    # refused. Deliberately not called brute force — no credential was tried.
    ("preauth_failure", re.compile(
        r"Connection reset by " + _WHO +
        r"(?:(?P<username>\S+) )?(?P<source_ip>" + IP + r") port")),

    ("preauth_failure", re.compile(
        r"Unable to negotiate with (?P<source_ip>" + IP + r") port")),

    ("preauth_failure", re.compile(
        r"banner exchange: Connection from (?P<source_ip>" + IP + r") port")),

    ("service_started", re.compile(r"Started ssh\.service")),

    ("service_stopped", re.compile(r"Stopped ssh\.service")),
]


PAM_EVENTS = {
    "authentication_failure",
    "multiple_auth_failures",
    "user_unknown",
}

SCHEMA_FIELDS = ("username", "source_ip")


def identify_event(line):
    """
    Parse one log line into a normalized event, or None if no pattern claims
    it. The log format is detected from the line itself.
    """

    envelope = parse_line(line)

    if envelope is None:
        return None

    timestamp, host, process, message = envelope

    # The line may be from cron, sudo or dovecot sharing the same file.
    if process not in SSH_PROCESSES:
        return None

    for event_type, pattern in SSH_PATTERNS:

        match = pattern.search(message)

        if not match:
            continue

        fields = {k: v for k, v in match.groupdict().items() if v is not None}
        details = {
            key: fields.pop(key)
            for key in list(fields)
            if key not in SCHEMA_FIELDS
        }

        if event_type in PAM_EVENTS:
            values = key_values(message)
            fields["source_ip"] = values.pop("rhost", None)
            # PAM names the targeted account `user=`. Promote it, or root
            # targeting is invisible to every detector that keys on username.
            fields.setdefault("username", values.pop("user", None))
            details.update(values)

        if "count" in details:
            details["count"] = int(details["count"])

        return create_event(
            timestamp=timestamp,
            log_source=LOG_SOURCE,
            event_type=event_type,
            host=host,
            details=details,
            **fields
        )

    return None
