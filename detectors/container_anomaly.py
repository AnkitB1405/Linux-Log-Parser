"""
`docker exec` into a running container is the container equivalent of an SSH
login — the highest-value signal in the Docker event stream.

The complication is that it is also completely routine: containers with a
HEALTHCHECK directive exec a probe every few seconds forever, and the event
stream does not mark them as probes. Real homelab capture shows immich_redis
running `redis-cli ping` and immich_machine_learning running `healthcheck.py`
alongside the genuine execs. An unfiltered rule fires every 30 seconds and is
switched off within a day, so suppression is the whole design.
"""

# Substrings that mark a command as a liveness probe rather than a person.
# Matched case-insensitively against the executed command.
PROBE_MARKERS = (
    "healthcheck",
    "health_check",
    "health-check",
    "ping",              # redis-cli ping, mysqladmin ping
    "pg_isready",
    "curl -f",
    "wget",
    "--spider",
    "nc -z",
    "/healthz",
)

# An interactive shell inside a container is a different thing from a scripted
# command: it is somebody at a keyboard.
SHELL_MARKERS = ("sh", "bash", "ash", "zsh", "dash")


def detect_container_anomaly(events):

    alerts = []

    for event in events:

        # exec_create and exec_start both fire for one exec, sharing an
        # execID. exec_create comes first and carries the command, so keying
        # on it alerts once per exec rather than twice.
        if event["event_type"] != "container_exec_created":
            continue

        command = event["details"].get("command")

        if command is None or is_probe(command):
            continue

        shell = is_shell(command)

        alerts.append({
            "severity": "high" if shell else "medium",
            "alert_type": "container_exec",
            "service": event["log_source"],
            "container": event["details"].get("name"),
            "image": event["details"].get("image"),
            "command": command,
            "timestamp": event["timestamp"],
            "event_ids": [event["id"]],
            "recommended_action":
                "interactive shell in a container — confirm who ran it"
                if shell else
                "confirm this exec was expected"
        })

    return alerts


def is_probe(command):
    lowered = command.lower()

    return any(marker in lowered for marker in PROBE_MARKERS)


def is_shell(command):
    """
    True when the command invokes a shell. The binary may be bare or a full
    path, so compare on the last path segment of the first token.
    """

    first = command.split()[0] if command.split() else ""

    return first.rsplit("/", 1)[-1] in SHELL_MARKERS
