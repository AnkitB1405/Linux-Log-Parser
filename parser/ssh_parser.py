def parse_failed_login(line):
    """
    Extract username and source IP
    from a failed SSH login event.
    """

    parts = line.split()

    user_index = parts.index("user")
    username = parts[user_index + 1]

    from_index = parts.index("from")
    source_ip = parts[from_index + 1]

    return {
        "event_type": "failed_login",
        "username": username,
        "source_ip": source_ip,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }

def parse_successful_login(line):
    """
    Extract username and source IP
    from a successful SSH login event.
    """

    parts = line.split()

    for_index = parts.index("for")
    username = parts[for_index + 1]

    from_index = parts.index("from")
    source_ip = parts[from_index + 1]

    return {
        "event_type": "successful_login",
        "username": username,
        "source_ip": source_ip,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }
    

def parse_session_opened(line):

    parts = line.split()

    user_index = parts.index("user")
    username = parts[user_index + 1].split("(")[0]

    by_index = parts.index("by")
    initiated_by = parts[by_index + 1].split("(")[0]

    return {
        "event_type": "session_opened",
        "username": username,
        "initiated_by": initiated_by,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }

def parse_invalid_user(line):

    parts = line.split()

    user_index = parts.index("user")
    username = parts[user_index + 1]

    from_index = parts.index("from")
    source_ip = parts[from_index + 1]

    return {
        "event_type": "invalid_user",
        "username": username,
        "source_ip": source_ip,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }

def parse_connection_closed(line):

    parts = line.split()

    user_index = parts.index("user")
    username = parts[user_index + 1]

    ip = parts[user_index + 2]

    return {
        "event_type": "connection_closed",
        "username": username,
        "source_ip": ip,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }

def parse_auth_failure(line):

    return {
        "event_type": "authentication_failure",
        "date": line.split()[0] + " " + line.split()[1],
        "time": line.split()[2]
    }

def parse_multiple_failures(line):

    parts = line.split()

    count = int(parts[1])

    return {
        "event_type": "multiple_auth_failures",
        "count": count,
        "date": parts[0] + " " + parts[1],
        "time": parts[2]
    }

def parse_service_started(line):

    return {
        "event_type": "service_started",
        "service": "ssh",
        "date": line.split()[0] + " " + line.split()[1],
        "time": line.split()[2]
    }


def parse_service_stopped(line):

    return {
        "event_type": "service_stopped",
        "service": "ssh",
        "date": line.split()[0] + " " + line.split()[1],
        "time": line.split()[2]
    }

def identify_event(line):
    """
    Identify the SSH event type from a log line.
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
    
    elif "authentication failure" in line:
        return parse_auth_failure(line)
    
    elif "more authentication failures" in line:
        return parse_multiple_failures(line)
    
    elif "Started ssh.service" in line:
        return parse_service_started(line)

    elif "Stopped ssh.service" in line:
        return parse_service_stopped(line)

    return None