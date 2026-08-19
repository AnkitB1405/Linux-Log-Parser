import re
from datetime import datetime

from parser.event_schema import create_event

LOG_SOURCE = "ssh"


# --- Envelope --------------------------------------------------------------
#
# Everything before the message body. This is the layer that changes when the
# parser moves to another machine — journald, rsyslog and RFC5424 wrap lines
# differently — so it is kept separate from the message patterns below, which
# come from OpenSSH's own source and read the same on every distro.
#
#   Jun 11 15:00:00 Sentinel sshd-session[200001]: Failed password for root ...
#   |--- timestamp ---| |-host-| |-process-||pid|  |-------- message -------|

SYSLOG = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    # ponytail: `process` is the dispatch key once a second log source lands
    # (sshd-session -> SSH_PATTERNS, dockerd -> DOCKER_PATTERNS, ...).
    r"(?P<process>[\w./-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)


# --- Message patterns ------------------------------------------------------
#
# One row per event type; first match wins. Named groups `username` and
# `source_ip` are promoted onto the event, every other group lands in
# `details`. Adding an event type is adding a row, not editing control flow.
#
# Unlike the substring chain this replaces, the ordering is no longer
# load-bearing: each pattern is specific enough that it cannot claim another
# row's lines. "PAM 2 more authentication failures" no longer has to be tested
# before "authentication failure" — the latter now requires a `pam_x(...):`
# prefix that the count line does not have.

IP = r"[0-9a-fA-F.:]+"

SSH_PATTERNS = [
    # ponytail: password only, to hold the current event set. Widen to
    # `(?P<auth_method>password|publickey)` to pick up the key-based logins
    # already sitting unparsed in the fixture.
    ("successful_login", re.compile(
        r"Accepted password for (?P<username>\S+) from (?P<source_ip>\S+)")),

    ("failed_login", re.compile(
        r"Failed password for (?:invalid user )?(?P<username>\S+) "
        r"from (?P<source_ip>\S+)")),

    ("invalid_user", re.compile(
        r"Invalid user (?:(?P<username>\S+) )?from (?P<source_ip>\S+)")),

    ("session_opened", re.compile(
        r"session opened for user (?P<username>[^(\s]+)\S* "
        r"by (?P<initiated_by>[^(\s]*)")),

    ("connection_closed", re.compile(
        r"Connection closed by (?:(?:invalid|authenticating) user )?"
        r"(?:(?P<username>\S+) )?(?P<source_ip>" + IP + r") port")),

    ("multiple_auth_failures", re.compile(
        r"PAM (?P<count>\d+) more authentication failures")),

    ("authentication_failure", re.compile(
        r"(?P<auth_module>\w+)\([^)]+\): authentication failure;")),

    ("service_started", re.compile(r"Started ssh\.service")),

    ("service_stopped", re.compile(r"Stopped ssh\.service")),
]

# PAM writes its context as `key=value` tokens rather than prose:
#   logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.10
# Order is not guaranteed, so scan for pairs instead of describing a layout.
KEY_VALUE = re.compile(r"(\w+)=(\S*)")

PAM_EVENTS = {"authentication_failure", "multiple_auth_failures"}

SCHEMA_FIELDS = ("username", "source_ip")


def parse_timestamp(stamp):
    # ponytail: syslog lines carry no year, so every timestamp lands in 1900.
    # Harmless while detectors only use deltas inside one file; breaks across
    # a Dec->Jan boundary. Fix by taking the year from the file mtime or by
    # consuming `journalctl -o short-iso` output.
    return datetime.strptime(stamp, "%b %d %H:%M:%S")


def identify_event(line):
    """
    Parse one syslog line into a normalized event, or None if no pattern
    claims it.
    """

    envelope = SYSLOG.match(line)

    if not envelope:
        return None

    message = envelope["message"]

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
            values = {k: v or None for k, v in KEY_VALUE.findall(message)}
            fields["source_ip"] = values.pop("rhost", None)
            details.update(values)

        if "count" in details:
            details["count"] = int(details["count"])

        return create_event(
            timestamp=parse_timestamp(envelope["timestamp"]),
            log_source=LOG_SOURCE,
            event_type=event_type,
            host=envelope["host"],
            details=details,
            **fields
        )

    return None
