"""
Apache / Nginx access and error logs.

This is the source token-index parsing could never read. A combined-format line
holds two quoted fields that contain arbitrary spaces — the request and the
user agent — so `line.split()` produces a different token count per line and no
fixed index means anything:

    172.17.0.1 - - [31/Aug/2026:12:10:44 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.00 (Nikto/2.5.0) ..."
                                                                                          ^ 12 tokens of user agent

Apache and Nginx share the combined format, so one parser serves both. Nginx
commonly appends a trailing field (`$http_x_forwarded_for`), which is why the
tail of the pattern is optional rather than fixed.
"""

import re
from datetime import datetime

from parser.event_schema import create_event

LOG_SOURCE = "web"

# Common Log Format plus the two combined-format fields. Quoted runs are
# matched as quoted runs rather than `\S+` precisely because they contain
# spaces.
#
# `(?:[^"\\]|\\.)*` — anything that is not a quote or a backslash, OR a
# backslash and whatever follows it. A plain `[^"]*` stops at the first
# escaped quote, and Apache escapes quotes inside the request as `\"`.
#
# That is not a cosmetic difference. Against 100,445 real AIT lines the naive
# form dropped 100 of them, and every single one was an attack: XSS and
# command-injection payloads carry quotes, ordinary browsing does not. The
# parser was silently discarding exactly the traffic worth seeing.
QUOTED = r'(?:[^"\\]|\\.)*'

ACCESS = re.compile(
    r'^(?P<source_ip>\S+) \S+ (?P<username>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>' + QUOTED + r')" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>' + QUOTED + r')" "(?P<user_agent>' + QUOTED + r')")?'
)

#   [Wed Aug 31 12:10:44.123456 2026] [php:error] [pid 12] [client 1.2.3.4:5432] message
ERROR = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\] \[(?P<module>[^\]]+)\]'
    r'(?: \[pid [^\]]+\])?'
    r'(?: \[client (?P<source_ip>[^\]\s:]+)(?::\d+)?\])?'
    r' (?P<message>.*)$'
)

REQUEST = re.compile(r'^(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>\S+))?$')

# Scanners announce themselves in the User-Agent by default. Anyone who changes
# it is not caught here — this is the cheap half of the signal, not all of it.
#
# Deliberately excluded: curl, wget, python-requests, Go-http-client. Those are
# generic HTTP clients, not scanning tools — every health check, cron job and
# deploy script uses one. Treating automation as attack is the same mistake as
# alerting on container health-check execs.
SCANNER_AGENTS = (
    "nikto", "sqlmap", "nmap", "masscan", "dirbuster", "gobuster",
    "wpscan", "acunetix", "nessus", "openvas", "zgrab", "wfuzz", "feroxbuster",
)

# Status classes become event types because event_type is what every detector
# filters on. The raw code stays in details.
STATUS_EVENTS = [
    (lambda s: s == 404, "http_not_found"),
    (lambda s: s in (401, 403), "http_auth_failure"),
    (lambda s: 400 <= s < 500, "http_client_error"),
    (lambda s: s >= 500, "http_server_error"),
]


def identify_event(line):
    """One access- or error-log line to a normalized event, or None."""

    line = line.strip()

    if not line:
        return None

    match = ACCESS.match(line)

    if match:
        return build_access(match)

    match = ERROR.match(line)

    if match:
        return build_error(match)

    return None


def build_access(match):
    fields = match.groupdict()
    status = int(fields["status"])

    request = REQUEST.match(fields["request"] or "")
    agent = fields.get("user_agent") or ""

    details = {
        "status": status,
        "method": request["method"] if request else None,
        "path": request["path"] if request else None,
        "protocol": request["protocol"] if request else None,
        # Kept raw when it does not parse: a malformed request line is itself
        # worth seeing, and dropping it would hide the interesting ones.
        "raw_request": None if request else fields["request"],
        "size": None if fields["size"] == "-" else int(fields["size"]),
        "referer": none_if_dash(fields.get("referer")),
        "user_agent": none_if_dash(agent),
        "scanner_agent": next(
            (name for name in SCANNER_AGENTS if name in agent.lower()), None),
    }

    return create_event(
        timestamp=parse_timestamp(fields["timestamp"]),
        log_source=LOG_SOURCE,
        event_type=classify(status),
        host=None,
        username=none_if_dash(fields["username"]),
        source_ip=fields["source_ip"],
        details={k: v for k, v in details.items() if v is not None},
    )


def build_error(match):
    fields = match.groupdict()

    return create_event(
        timestamp=parse_error_timestamp(fields["timestamp"]),
        log_source=LOG_SOURCE,
        event_type="http_error_log",
        host=None,
        username=None,
        source_ip=fields.get("source_ip"),
        details={"module": fields["module"], "message": fields["message"]},
    )


def classify(status):
    for matches, event_type in STATUS_EVENTS:
        if matches(status):
            return event_type

    return "http_request"


def none_if_dash(value):
    return None if value in (None, "", "-") else value


def parse_timestamp(stamp):
    """`31/Aug/2026:12:10:44 +0000` — a real year and offset, unlike syslog."""

    return datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z")


def parse_error_timestamp(stamp):
    """`Wed Aug 31 12:10:44.123456 2026`."""

    return datetime.strptime(stamp, "%a %b %d %H:%M:%S.%f %Y")
