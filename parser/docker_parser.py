"""
Parser for `docker events --format '{{json .}}'`.

Deliberately not regex. The stream is already structured, so json.loads plus a
dict lookup does the whole job — regexing JSON would be strictly worse. The
envelope/message split still holds: JSON structure is Docker's envelope, and
ACTIONS is its message table.

Reads the file a collector wrote. Docker keeps its event log in memory only and
loses it when the daemon restarts, so there is no history to read after the
fact — something must be recording while the events happen.
"""

import json
from datetime import datetime

from parser.event_schema import create_event

LOG_SOURCE = "docker"

# (Type, Action) -> event_type. Action is the part before any ": " suffix.
# Adding an event type is adding a row.
ACTIONS = {
    ("container", "create"): "container_created",
    ("container", "start"): "container_started",
    ("container", "stop"): "container_stopped",
    ("container", "restart"): "container_restarted",
    ("container", "kill"): "container_killed",
    ("container", "die"): "container_died",
    ("container", "destroy"): "container_destroyed",
    ("container", "attach"): "container_attached",
    ("container", "exec_create"): "container_exec_created",
    ("container", "exec_start"): "container_exec_started",
    ("container", "exec_die"): "container_exec_died",
    ("network", "connect"): "network_connected",
    ("network", "disconnect"): "network_disconnected",
    ("image", "pull"): "image_pulled",
    ("volume", "mount"): "volume_mounted",
}

# Actor.Attributes is open-ended and mostly build metadata: 84 sample events
# carried 29 distinct keys, including 11 com.docker.compose.* and 8
# org.opencontainers.image.*. Promoting all of them would bury every event, so
# only the operationally meaningful ones are kept.
KEPT_ATTRIBUTES = (
    "name",           # container name — the entity every detector needs
    "image",
    "execID",
    "exitCode",       # on die and exec_die
    "signal",         # on kill
    "execDuration",
)


def parse_action(action):
    """
    Split Docker's Action field.

    It is not a bare enum for exec events — the command is appended after a
    colon, so `action == "exec_create"` matches nothing:

        "exec_create: sh -c cat /etc/passwd"  ->  ("exec_create", "sh -c cat /etc/passwd")
        "exec_die"                            ->  ("exec_die", None)
    """

    name, separator, command = action.partition(": ")

    return name, command if separator else None


def identify_event(line):
    """Parse one JSON event line into a normalized event, or None."""

    line = line.strip()

    if not line:
        return None

    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    action_name, command = parse_action(raw.get("Action", ""))
    event_type = ACTIONS.get((raw.get("Type"), action_name))

    if event_type is None:
        return None

    attributes = (raw.get("Actor") or {}).get("Attributes") or {}

    details = {
        key: attributes[key]
        for key in KEPT_ATTRIBUTES
        if key in attributes
    }

    details["container_id"] = (raw.get("Actor") or {}).get("ID")

    # The executed command is the security signal on an exec event — it is the
    # difference between a health check and someone opening a shell.
    if command:
        details["command"] = command

    if "exitCode" in details:
        details["exitCode"] = int(details["exitCode"])

    return create_event(
        timestamp=parse_timestamp(raw),
        log_source=LOG_SOURCE,
        event_type=event_type,
        host=raw.get("scope"),
        details=details,
        # Docker events carry neither a user nor a source address. Left None
        # rather than invented; container identity lives in details["name"].
        username=None,
        source_ip=None,
    )


def parse_timestamp(raw):
    """
    timeNano is nanoseconds since epoch, time is whole seconds. Either way
    this is a real timestamp with a real year — unlike BSD syslog.
    """

    nanos = raw.get("timeNano")

    if nanos:
        return datetime.fromtimestamp(nanos / 1_000_000_000)

    return datetime.fromtimestamp(raw.get("time", 0))
