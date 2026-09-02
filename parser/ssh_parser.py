import re
from datetime import datetime

from parser.event_schema import create_event

LOG_SOURCE = "ssh"


# --- Envelopes -------------------------------------------------------------
#
# The envelope is the syslog wrapper the operating system puts around a
# message; the message itself is written by OpenSSH and reads the same
# everywhere. Only the envelope varies by machine, so it is the only thing
# that needs a per-machine variant.
#
# Envelopes are tried in order and the first to match wins, which is how the
# parser auto-detects the log format. No caller declares which distro produced
# a line — a mixed input file is parsed correctly line by line.
#
#   Mint  2026-08-19T10:09:15.247212+05:30 shadow sshd[3344602]: Failed ...
#   Kali  Aug 19 10:09:15 shadow sshd-session[3344602]: Failed ...

_TAIL = (
    r"\s+(?P<host>\S+)"
    r"\s+(?P<process>[\w./-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)


def _parse_rfc3339(stamp):
    """Linux Mint / rsyslog. Carries a real year and offset, so this is exact."""

    return datetime.fromisoformat(stamp)


# BSD syslog lines carry no year, so one has to be supplied. The reference
# point is the log file's mtime where the caller knows it (see
# set_reference_time), otherwise now — which is right for a live tail and for
# a file being written today.
REFERENCE = datetime.now()


def set_reference_time(when):
    """Anchor year-less BSD timestamps to a known point, e.g. a file's mtime."""

    global REFERENCE
    REFERENCE = when


def _parse_bsd(stamp):
    """
    A year-less `Aug 19 10:09:15`, resolved against REFERENCE.

    Rollover matters: a file written in January still holds December lines
    from the year before. A month later than the reference is therefore last
    year's, not next year's — without this, a Dec->Jan span produces a delta
    of roughly minus 365 days and every time-window detector silently stops
    firing.
    """

    parsed = datetime.strptime(f"{REFERENCE.year} {stamp}", "%Y %b %d %H:%M:%S")

    if parsed.month > REFERENCE.month:
        parsed = parsed.replace(year=REFERENCE.year - 1)

    return parsed


ENVELOPES = [
    # Linux Mint (rsyslog -> /var/log/auth.log). The primary target.
    ("rfc3339", _parse_rfc3339, re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z))" + _TAIL)),

    # journald short output (Kali) and classic BSD syslog (Metasploitable).
    # The same pattern serves both: the optional [pid] group matches
    # `sshd-session[123]` on OpenSSH >= 9.8 and `sshd[123]` on older builds.
    ("bsd", _parse_bsd, re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})" + _TAIL)),
]


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

# Several daemons write context as `key=value` tokens rather than prose:
#
#   PAM      logname= uid=0 tty=ssh ruser= rhost=45.155.205.211  user=root
#   dockerd  time="2026-08-21T13:24:48+05:30" level=info msg="Daemon started"
#
# Order is not guaranteed, so scan for pairs instead of describing a layout.
# The value is either a quoted run — which may contain spaces — or a bare
# token. Quoted is tried first: with a plain `\S*` the dockerd line above
# truncates msg to `"Daemon`, silently dropping the rest of the message.
KEY_VALUE = re.compile(r'(\w+)=("[^"]*"|\S*)')

PAM_EVENTS = {
    "authentication_failure",
    "multiple_auth_failures",
    "user_unknown",
}

SCHEMA_FIELDS = ("username", "source_ip")


def key_values(message):
    """`key=value` pairs from a message, quotes stripped, empties as None."""

    return {
        key: value.strip('"') or None
        for key, value in KEY_VALUE.findall(message)
    }


def parse_line(line):
    """Split a raw line into (timestamp, host, process, message), or None."""

    for _name, parse_timestamp, pattern in ENVELOPES:

        match = pattern.match(line)

        if match:
            return (
                parse_timestamp(match["timestamp"]),
                match["host"],
                match["process"],
                match["message"],
            )

    return None


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
