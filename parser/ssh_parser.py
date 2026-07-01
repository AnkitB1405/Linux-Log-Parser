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
    

def identify_event(line):
    """
    Identify the SSH event type from a log line.
    """

    if "Accepted password" in line:
        return parse_successful_login(line)

    elif "Failed password" in line:
        return parse_failed_login(line)

    elif "Invalid user" in line:
        parts = line.split()
        return {
            "event_type": "invalid_user",
            "date": parts[0] + " " + parts[1],
            "time": parts[2]
        }

    elif "session opened" in line:
        parts = line.split()
        return {
            "event_type": "session_opened",
            "date": parts[0] + " " + parts[1],
            "time": parts[2]
        }

    elif "Connection closed" in line:
        parts = line.split()
        return {
            "event_type": "connection_closed",
            "date": parts[0] + " " + parts[1],
            "time": parts[2]
        }

    return None