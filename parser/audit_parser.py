"""
Linux audit daemon logs — where post-exploitation is actually visible.

The AIT evaluation is the reason this exists. Thirty-seven of its forty missed
attack steps are webshell commands — `id`, `whoami`, `netstat`, `cat
/etc/passwd` — and none are detectable from web logs: the attacker drives a
legitimate application endpoint from a legitimate user's address, and the
command lives in a POST body Apache never records.

Those commands run as processes, and auditd records every execve.

STRUCTURALLY DIFFERENT FROM EVERY OTHER PARSER HERE

One audit event spans several lines, joined by the `msg=audit(epoch:serial)`
key:

    type=SYSCALL   msg=audit(1582934417.952:876201): syscall=59 ... comm="sh"
    type=EXECVE    msg=audit(1582934417.952:876201): argc=2 a0="id" a1="-u"
    type=PATH      msg=audit(1582934417.952:876201): name="/usr/bin/id" ...
    type=PROCTITLE msg=audit(1582934417.952:876201): proctitle=2F62696E2F7368...

So the usual `identify_event(line)` contract cannot work. `group_records()`
assembles the lines of one event first, and `identify_event()` then takes that
whole group as one string — text in, event out, same as everywhere else, just a
larger piece of text.
"""

import binascii
import re
from datetime import datetime

from parser.envelope import key_values
from parser.event_schema import create_event

LOG_SOURCE = "audit"

# Every record of one event carries the same (epoch, serial) pair.
STAMP = re.compile(r"msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")

RECORD_TYPE = re.compile(r"^type=(?P<type>\w+)")

# EXECVE lists the real argv: a0="id" a1="-u". PROCTITLE carries the same thing
# as one blob, hex-encoded when it holds anything awkward and quoted when it
# does not — both forms appear in the same file.
EXECVE_ARG = re.compile(r'\ba(\d+)="([^"]*)"')
PROCTITLE = re.compile(r"proctitle=(?:\"(?P<quoted>[^\"]*)\"|(?P<hex>[0-9A-Fa-f]+))")

# Only the syscalls worth building events from. The sample is 283,633 SYSCALL
# records for 1,067 executions — reading everything would bury the signal.
EXECVE = 59
OPEN_SYSCALLS = {2, 257}        # open, openat

# File opens are 94% of auditd's output — 81,053 of them for 1,067 executions
# in the sample, nearly all library loads and config reads. Emitting them
# wholesale buries the signal, so only opens of files that matter become
# events. Same reasoning as the Docker attribute allowlist.
WATCHED_PATHS = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/passwd", "/etc/group",
    "authorized_keys", "id_rsa", "id_ed25519", "/root/.ssh",
    "/etc/ssh/sshd_config", "/etc/crontab",
    ".aws/credentials", ".kube/config", "/etc/ld.so.preload",
    # "/etc/cron." and "/var/spool/cron" were here and are deliberately gone:
    # run-parts opens every /etc/cron.daily script on schedule, so reading one
    # is cron working normally. The signal is a cron file being WRITTEN, which
    # needs a syscall filter on create/write rather than a path match on open.
)

# auditd records numeric ids; resolving them needs the host's passwd file,
# which is not in the log. These are the fixed Debian/Ubuntu assignments that
# matter for this work — anything else stays numeric in `details`.
KNOWN_UIDS = {
    "0": "root",
    "33": "www-data",
    "8": "mail",
    "1": "daemon",
}


def group_records(lines):
    """
    Yield (line_indices, joined_text) per audit event, in first-seen order.

    Records of one event are usually adjacent but not guaranteed to be, so they
    are collected by key rather than by position. The indices come back because
    an evaluation against line-aligned labels has to map a multi-line event to
    the union of its lines' labels.
    """

    groups = {}
    order = []

    for index, line in enumerate(lines):
        stamp = STAMP.search(line)

        if not stamp:
            continue

        key = (stamp["epoch"], stamp["serial"])

        if key not in groups:
            groups[key] = ([], [])
            order.append(key)

        groups[key][0].append(index)
        groups[key][1].append(line.rstrip("\n"))

    for key in order:
        indices, records = groups[key]
        yield indices, "\n".join(records)


def identify_event(record):
    """One assembled audit event to a normalized event, or None."""

    stamp = STAMP.search(record)

    if not stamp:
        return None

    types = set(RECORD_TYPE.match(l)["type"]
                for l in record.splitlines() if RECORD_TYPE.match(l))

    fields = key_values(record)
    timestamp = datetime.fromtimestamp(float(stamp["epoch"]))

    event_type, details = classify(types, fields, record)

    if event_type is None:
        return None

    uid = fields.get("uid")
    details.update({
        "uid": uid,
        "auid": fields.get("auid"),
        "pid": fields.get("pid"),
        "ppid": fields.get("ppid"),
        "comm": strip(fields.get("comm")),
        "exe": strip(fields.get("exe")),
        "success": fields.get("success"),
        "audit_key": strip(fields.get("key")),
        "record_types": sorted(types),
    })

    return create_event(
        timestamp=timestamp,
        log_source=LOG_SOURCE,
        event_type=event_type,
        host=None,
        username=KNOWN_UIDS.get(uid),
        source_ip=strip(fields.get("addr")) or None,
        details={k: v for k, v in details.items() if v not in (None, "", "(null)")},
    )


def classify(types, fields, record):
    """(event_type, details) for an assembled event, or (None, {}) to skip."""

    syscall = fields.get("syscall")

    if "EXECVE" in types or syscall == str(EXECVE):
        return "process_executed", {
            "argv": argv(record),
            "command": " ".join(argv(record)) or None,
        }

    if "USER_AUTH" in types or "USER_ACCT" in types:
        result = strip(fields.get("res"))
        return ("audit_auth_failure" if result == "failed" else "audit_auth_success"), {
            "result": result,
            "terminal": strip(fields.get("terminal")),
        }

    if "LOGIN" in types:
        return "audit_login", {"session": fields.get("ses")}

    if "CRED_ACQ" in types:
        return "audit_credential_acquired", {}

    # SOCKADDR is deliberately not an event type yet: 4,181 in the sample and
    # roughly 300,000 at full scale, with nothing consuming them. An outbound
    # connection from a web process is a real signal, so add it when a detector
    # wants it rather than before.

    if syscall in {str(s) for s in OPEN_SYSCALLS} and "PATH" in types:
        path = first_path(record)

        if path and any(watched in path for watched in WATCHED_PATHS):
            return "audit_sensitive_file", {"path": path}

        return None, {}

    # A bare SYSCALL with nothing else attached is noise: 283,633 of them for
    # 1,067 executions in the sample.
    return None, {}


def argv(record):
    """
    The command line, preferring EXECVE's real arguments over PROCTITLE.

    PROCTITLE is truncated by the kernel at 4096 bytes and hex-encoded when it
    contains anything awkward; EXECVE lists each argument separately and is
    exact.
    """

    args = sorted(((int(n), v) for n, v in EXECVE_ARG.findall(record)))

    if args:
        return [v for _n, v in args]

    found = PROCTITLE.search(record)

    if not found:
        return []

    if found["quoted"] is not None:
        raw = found["quoted"]
    else:
        raw = binascii.unhexlify(found["hex"]).decode("utf-8", "replace")

    return [part for part in raw.split("\x00") if part]


def first_path(record):
    found = re.search(r'type=PATH[^\n]*\bname="([^"]+)"', record)

    return found.group(1) if found else None


def strip(value):
    return value.strip('"') if isinstance(value, str) else value
