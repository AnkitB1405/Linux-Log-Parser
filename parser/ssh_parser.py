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
        "source_ip": source_ip
    }

def identify_event(line):
    """
    Identify the SSH event type from a log line.
    """

    if "Accepted password" in line:
        return {
            "event_type": "successful_login"
        }

    elif "Failed password" in line:
        return {
            "event_type": "failed_login"
        }

    elif "Invalid user" in line:
        return {
            "event_type": "invalid_user"
        }

    elif "session opened" in line:
        return {
            "event_type": "session_opened"
        }

    elif "Connection closed" in line:
        return {
            "event_type": "connection_closed"
        }

    return None