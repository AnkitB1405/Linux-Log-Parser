"""
/var/log/auth.log — everything in it that is not sshd.

The file is the *authentication* log, not the SSH log. sudo, su, cron, polkit,
the shadow-suite account tools and every PAM-using service share it. That
sharing is why `ssh_parser` refuses lines whose process is not sshd, and why
this parser exists to pick up the rest.

The two parsers are disjoint by design: AUTH_PROCESSES deliberately excludes
sshd, sshd-session and sshd-auth, so no line is claimed twice and no event is
double-counted.

What this log is for, in security terms: SSH tells you who got *in*. auth.log
tells you what they did once inside — whether they escalated, whether they were
refused, and whether they left themselves a way back.

Line shapes here were captured from a real Debian host and a throwaway
container, not written from documentation.
"""

import re

from parser.envelope import key_values, parse_line
from parser.event_schema import create_event

LOG_SOURCE = "auth"

# Processes this parser answers for. sshd and its helpers are absent on
# purpose — ssh_parser owns those. `auth` is dovecot's PAM helper, which is how
# the AIT dataset's hydra attack appears.
AUTH_PROCESSES = {
    "sudo", "su",
    "useradd", "userdel", "usermod",
    "groupadd", "groupdel", "gpasswd",
    "passwd", "chpasswd", "chage",
    "CRON", "cron", "crond",
    "polkitd", "auth", "dovecot", "systemd-logind",
}

# `sudo:  analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id`
# TTY is absent when sudo runs without one, so it is optional rather than
# assumed. The command runs to end-of-line and may contain anything.
_SUDO_TAIL = (
    r"(?:TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>\S+) ; "
    r"USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)$"
)

AUTH_PATTERNS = [
    # --- sudo: the privilege boundary ------------------------------------
    ("sudo_denied", re.compile(
        r"^\s*(?P<username>\S+) : user NOT in sudoers ; " + _SUDO_TAIL)),

    ("sudo_auth_failure", re.compile(
        r"^\s*(?P<username>\S+) : (?P<attempts>\d+) incorrect password attempts? ; "
        + _SUDO_TAIL)),

    ("sudo_command", re.compile(
        r"^\s*(?P<username>\S+) : " + _SUDO_TAIL)),

    # sudo logs one failure twice: its own counter line (above, which carries
    # the attempt number and the command) and this PAM line. Counting both
    # inflates every failure, so the PAM copy gets its own type that detectors
    # ignore — the same treatment as group_shadow_synced.
    ("sudo_pam_failure", re.compile(
        r"pam_unix\(sudo:auth\): authentication failure;")),

    # --- su ---------------------------------------------------------------
    ("su_attempt", re.compile(
        r"^\(to (?P<target_user>\S+)\) (?P<username>\S+) on (?P<tty>\S+)")),

    # --- privilege sessions, from sudo and su alike ------------------------
    # `by X(uid=N)` names who escalated — the field that answers "who became
    # root", which the username alone does not.
    ("privilege_session_opened", re.compile(
        r"pam_unix\((?P<pam_service>su|su-l|sudo):session\): session opened for "
        r"user (?P<target_user>[^(\s]+)(?:\(uid=(?P<target_uid>\d+)\))?"
        r"(?: by (?P<username>[^(\s]*)(?:\(uid=(?P<uid>\d+)\))?)?")),

    ("privilege_session_closed", re.compile(
        r"pam_unix\((?:su|su-l|sudo):session\): session closed for "
        r"user (?P<target_user>\S+)")),

    # --- scheduled work: where persistence hides ---------------------------
    ("cron_session_opened", re.compile(
        r"pam_unix\(cron:session\): session opened for user (?P<username>[^(\s]+)")),

    ("cron_session_closed", re.compile(
        r"pam_unix\(cron:session\): session closed for user (?P<username>\S+)")),

    # --- account and group changes: where persistence is installed ---------
    ("account_created", re.compile(
        r"new user: name=(?P<target_user>[^,]+), UID=(?P<target_uid>\d+), "
        r"GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)")),

    ("account_deleted", re.compile(
        r"delete user '(?P<target_user>[^']+)'")),

    # Adding an account to a privileged group is the quietest way to keep root.
    #
    # usermod writes the same change twice — once for /etc/group and once for
    # /etc/gshadow. Counting both would double every membership change, so the
    # shadow copy gets its own event type that detectors ignore. `to group` and
    # `to shadow group` are naturally disjoint strings, so order is irrelevant.
    ("group_membership_added", re.compile(
        r"add '(?P<target_user>[^']+)' to group '(?P<group>[^']+)'")),

    ("group_membership_removed", re.compile(
        r"delete '(?P<target_user>[^']+)' from group '(?P<group>[^']+)'")),

    ("group_shadow_synced", re.compile(
        r"(?:add '(?P<added>[^']+)' to|delete '(?P<removed>[^']+)' from) "
        r"shadow group '(?P<group>[^']+)'")),

    ("group_deleted", re.compile(
        r"removed (?:shadow )?group '(?P<group>[^']+)'")),

    ("group_created", re.compile(
        r"new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")),

    ("password_changed", re.compile(
        r"password changed for (?P<target_user>\S+)")),

    # --- polkit: the desktop privilege path --------------------------------
    ("polkit_denied", re.compile(
        r"Operator of (?P<session>\S+) FAILED to authenticate to gain "
        r"authorization for action (?P<action>\S+)")),

    # --- any other PAM service: dovecot, exim, vsftpd ... ------------------
    # This is where AIT's hydra attack lives: pam_unix(dovecot:auth) with a
    # different username every line from one rhost.
    ("service_auth_failure", re.compile(
        r"pam_unix\((?P<pam_service>[\w-]+):auth\): authentication failure;")),

    ("service_user_unknown", re.compile(
        r"pam_unix\((?P<pam_service>[\w-]+):auth\): check pass; user unknown")),
]

# Events whose context arrives as PAM `key=value` tokens rather than prose.
PAM_EVENTS = {"sudo_pam_failure", "service_auth_failure", "service_user_unknown"}

SCHEMA_FIELDS = ("username", "source_ip")


def identify_event(line):
    """One auth.log line to a normalized event, or None if not ours."""

    envelope = parse_line(line)

    if envelope is None:
        return None

    timestamp, host, process, message = envelope

    # sshd lines in this same file belong to ssh_parser, not here.
    if process not in AUTH_PROCESSES:
        return None

    for event_type, pattern in AUTH_PATTERNS:

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
            fields.setdefault("username", values.pop("user", None)
                              or values.pop("ruser", None))
            details.update(values)

        details["process"] = process

        for key in ("attempts", "target_uid", "uid", "gid"):
            if key in details:
                details[key] = int(details[key])

        return create_event(
            timestamp=timestamp,
            log_source=LOG_SOURCE,
            event_type=event_type,
            host=host,
            details=details,
            **fields
        )

    return None
