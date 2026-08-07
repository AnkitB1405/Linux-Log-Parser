from datetime import datetime

from parser.event_schema import create_event

LOG_SOURCE = "ssh"


def parse_timestamp(line):

    parts = line.split()

    date = f"{parts[0]} {parts[1]}"
    time = parts[2]

    # ponytail: syslog lines carry no year, so every timestamp lands in 1900.
    # Harmless while detectors only use deltas inside one file; breaks across
    # a Dec->Jan boundary. Fix by taking the year from the file mtime or by
    # consuming `journalctl -o short-iso` output.
    timestamp = datetime.strptime(
        f"{date} {time}",
        "%b %d %H:%M:%S"
    )

    return timestamp


def parse_host(line):
    """
    Hostname sits directly after the timestamp:
    `Jun 11 15:00:00 Sentinel sshd-session[200001]: ...`
    """

    return line.split()[3]


def parse_username(parts):
    """
    Lines vary between `... for user X ...` and `... for X ...`.
    """

    if "user" in parts:
        return parts[parts.index("user") + 1]

    return parts[parts.index("for") + 1]


def parse_failed_login(line):
    """
    Extract username and source IP
    from a failed SSH login event.
    """

    parts = line.split()

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="failed_login",
        host=parse_host(line),
        username=parse_username(parts),
        source_ip=parts[parts.index("from") + 1]
    )


def parse_successful_login(line):
    """
    Extract username and source IP
    from a successful SSH login event.
    """

    parts = line.split()

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="successful_login",
        host=parse_host(line),
        username=parse_username(parts),
        source_ip=parts[parts.index("from") + 1]
    )


def parse_session_opened(line):

    parts = line.split()

    username = parts[parts.index("user") + 1].split("(")[0]
    initiated_by = parts[parts.index("by") + 1].split("(")[0]

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="session_opened",
        host=parse_host(line),
        username=username,
        details={"initiated_by": initiated_by}
    )


def parse_invalid_user(line):

    parts = line.split()

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="invalid_user",
        host=parse_host(line),
        username=parts[parts.index("user") + 1],
        source_ip=parts[parts.index("from") + 1]
    )


def parse_connection_closed(line):

    parts = line.split()
    by_index = parts.index("by")

    if "invalid" in parts:
        username = parts[by_index + 2]
        source_ip = parts[by_index + 3]

    else:
        username = parts[by_index + 1]
        source_ip = parts[by_index + 2]

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="connection_closed",
        host=parse_host(line),
        username=username,
        source_ip=source_ip
    )


def parse_key_values(parts, keys):
    """
    PAM lines carry `key=value` tokens: uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4
    """

    found = {key: None for key in keys}

    for item in parts:
        for key in keys:
            if item.startswith(f"{key}="):
                found[key] = item.split("=")[1] or None

    return found


def parse_auth_failure(line):

    parts = line.split()
    fields = parse_key_values(parts, ["uid", "euid", "tty", "ruser", "rhost"])

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="authentication_failure",
        host=parse_host(line),
        source_ip=fields["rhost"],
        details={
            "auth_module": "pam_unix",
            "uid": fields["uid"],
            "euid": fields["euid"],
            "tty": fields["tty"],
            "ruser": fields["ruser"]
        }
    )


def parse_multiple_failures(line):

    parts = line.split()
    fields = parse_key_values(parts, ["uid", "euid", "tty", "rhost"])

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="multiple_auth_failures",
        host=parse_host(line),
        source_ip=fields["rhost"],
        details={
            "count": int(parts[parts.index("PAM") + 1]),
            "uid": fields["uid"],
            "euid": fields["euid"],
            "tty": fields["tty"]
        }
    )


def parse_service_started(line):

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="service_started",
        host=parse_host(line)
    )


def parse_service_stopped(line):

    return create_event(
        timestamp=parse_timestamp(line),
        log_source=LOG_SOURCE,
        event_type="service_stopped",
        host=parse_host(line)
    )


def identify_event(line):
    """
    Identify the SSH event type from a log line.

    Order matters: "more authentication failures" must be tested before
    "authentication failure", or PAM count lines get misclassified.
    """

    if "Accepted password" in line:
        return parse_successful_login(line)

    elif "Failed password" in line:
        return parse_failed_login(line)

    elif "Invalid user" in line:
        return parse_invalid_user(line)

    elif "session opened" in line:
        return parse_session_opened(line)

    elif "Connection closed" in line:
        return parse_connection_closed(line)

    elif "more authentication failures" in line:
        return parse_multiple_failures(line)

    elif "authentication failure" in line:
        return parse_auth_failure(line)

    elif "Started ssh.service" in line:
        return parse_service_started(line)

    elif "Stopped ssh.service" in line:
        return parse_service_stopped(line)

    return None
