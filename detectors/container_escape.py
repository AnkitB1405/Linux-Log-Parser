"""
Containers configured with a route out onto the host.

These are not events — they are properties that persist. Portainer holds
/var/run/docker.sock every second of every day, legitimately, because that is
what Portainer is. Alerting on the *state* means alerting on your own
infrastructure forever, which is how a detector gets muted.

So this alerts on what is NOT expected: findings that are not already on the
allowlist for that container. Until retention exists (Phase 5) the allowlist is
the baseline; after it, the allowlist becomes the seed and the baseline is
learned.

Requires enrichment. `docker events` does not carry any of these fields —
verified against 84 captured events, where Privileged, PidMode, Binds, CapAdd
and HostConfig appear exactly zero times. The collector attaches HostConfig
from `docker inspect` at capture time; events without it are skipped rather
than assumed safe.
"""

# Host paths where a read-write bind mount means the container can rewrite the
# machine. Ordinary data volumes (/docker/*, /nas/*, named volumes) are not
# here on purpose — most of the homelab uses them and they are how Docker
# persistence normally works.
SENSITIVE_PATHS = (
    "/",
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/var/lib/docker",
)

# Capabilities that hand back most of what the container gave up.
DANGEROUS_CAPS = ("SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH")

# Expected findings per container, keyed on NAME rather than id: compose
# destroys and recreates containers, so ids change on every `up` and an
# id-keyed baseline would re-alert on every restart.
#
# Seeded from the homelab's containers as of 2026-08-23. A finding listed here
# is known and deliberate; anything else on that container is new.
ALLOWED = {
    "portainer": {"docker_socket"},
}


def detect_container_escape(events):

    alerts = []

    for event in events:

        if event["event_type"] not in ("container_created", "container_started"):
            continue

        config = event["details"].get("host_config")

        # Not enriched — the collector was not running, or this is an archived
        # capture. Absence of evidence, so say nothing.
        if not config:
            continue

        name = event["details"].get("name")
        findings = assess(config) - ALLOWED.get(name, set())

        if not findings:
            continue

        alerts.append({
            "severity": "high",
            "alert_type": "container_escape_risk",
            "service": event["log_source"],
            "container": name,
            "image": event["details"].get("image"),
            "findings": sorted(findings),
            "timestamp": event["timestamp"],
            "event_ids": [event["id"]],
            "recommended_action":
            "confirm this container is meant to hold host access; "
            "if not, stop it and audit what it reached"
        })

    return alerts


def assess(config):
    """Every escape route this HostConfig grants, as a set of tags."""

    findings = set()

    if config.get("Privileged"):
        findings.add("privileged")

    if config.get("PidMode") == "host":
        findings.add("pid_host")

    if config.get("NetworkMode") == "host":
        findings.add("network_host")

    if config.get("IpcMode") == "host":
        findings.add("ipc_host")

    for option in config.get("SecurityOpt") or []:
        if "unconfined" in option or option == "label=disable":
            findings.add("security_disabled")

    for capability in config.get("CapAdd") or []:
        if capability.upper().removeprefix("CAP_") in DANGEROUS_CAPS:
            findings.add(f"cap_{capability.lower().removeprefix('cap_')}")

    for bind in config.get("Binds") or []:
        findings |= assess_bind(bind)

    return findings


def assess_bind(bind):
    """
    One `host:container[:opts]` bind. Read-only mounts of sensitive paths are
    recorded but not raised — reading /etc is a much smaller thing than
    rewriting it.
    """

    parts = bind.split(":")
    host_path = parts[0]
    options = parts[2] if len(parts) > 2 else ""

    if host_path.rstrip("/").endswith("docker.sock"):
        # Anything holding the socket can start a privileged container, so
        # this is equivalent to root on the host regardless of ro/rw.
        return {"docker_socket"}

    if "ro" in options.split(","):
        return set()

    normalized = host_path.rstrip("/") or "/"

    if normalized in SENSITIVE_PATHS:
        return {f"sensitive_mount:{normalized}"}

    return set()
