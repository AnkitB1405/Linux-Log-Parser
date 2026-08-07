import uuid


def create_event(
    timestamp,
    log_source,
    event_type,
    severity=None,
    host=None,
    details=None,
    username=None,
    source_ip=None
):
    """
    Build a normalized event.

    Every parser routes through this, so the top-level shape is identical
    no matter which log source produced the line. Source-specific fields
    go in `details`.

    `username` and `source_ip` are promoted to the top level rather than
    living in `details` because every detector correlates on them, and
    they are meaningful for every planned log source (ssh, syslog, auth,
    apache). Anything that is only meaningful to one source stays in
    `details`.
    """

    return {
        # ponytail: 48-bit id, ample for linking alerts to events within a
        # run. Use the full uuid4 if events ever land in a shared store.
        "id": uuid.uuid4().hex[:12],
        "timestamp": timestamp,
        "log_source": log_source,
        "host": host,
        "event_type": event_type,
        "severity": severity,
        "username": username,
        "source_ip": source_ip,
        "details": details or {}
    }
