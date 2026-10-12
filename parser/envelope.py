"""
The syslog envelope — shared by every parser that reads a syslog-family file.

A syslog line has two halves written by two different programs:

    Aug 19 10:09:15 shadow sshd[3344602]: Failed password for root from 1.2.3.4
    └──────────── ENVELOPE ────────────┘  └──────────── MESSAGE ──────────────┘
         written by the OS                     written by the application

They vary independently. The envelope changes when you change machine; the
message changes only when the application itself changes. So a new machine
costs an envelope row here, and a new application costs a message table in its
own parser — neither costs a parser.

This module owns the envelope and nothing else. `ssh_parser` and `auth_parser`
both read it, which is the point: they parse different applications out of the
same wrapper, and `auth.log` genuinely contains both.
"""

import re
from datetime import datetime

_TAIL = (
    r"\s+(?P<host>\S+)"
    r"\s+(?P<process>[\w./-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)

# BSD syslog lines carry no year, so one has to be supplied. The reference
# point is the log file's mtime where the caller knows it (see
# set_reference_time), otherwise now — which is right for a live tail and for
# a file being written today.
REFERENCE = datetime.now()


def set_reference_time(when):
    """Anchor year-less BSD timestamps to a known point, e.g. a file's mtime."""

    global REFERENCE
    REFERENCE = when


def _parse_rfc3339(stamp):
    """rsyslog's default on modern Debian/Mint. Real year and offset — exact."""

    return datetime.fromisoformat(stamp)


def _parse_bsd(stamp):
    """
    A year-less `Aug 19 10:09:15`, resolved against REFERENCE.

    Rollover matters: a file written in January still holds December lines from
    the year before. A month later than the reference is therefore last year's,
    not next year's — without this a Dec->Jan span produces a delta of roughly
    minus 365 days and every time-window detector silently stops firing.
    """

    parsed = datetime.strptime(f"{REFERENCE.year} {stamp}", "%Y %b %d %H:%M:%S")

    if parsed.month > REFERENCE.month:
        parsed = parsed.replace(year=REFERENCE.year - 1)

    return parsed


# Tried in order; first match wins. This is the format auto-detection — no
# caller declares which distro produced a line, and a file mixing formats
# parses correctly line by line.
ENVELOPES = [
    ("rfc3339", _parse_rfc3339, re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z))" + _TAIL)),

    ("bsd", _parse_bsd, re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})" + _TAIL)),
]


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


def key_values(message):
    """`key=value` pairs from a message, quotes stripped, empties as None."""

    return {
        key: value.strip('"') or None
        for key, value in KEY_VALUE.findall(message)
    }
