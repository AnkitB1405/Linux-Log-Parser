def create_event(
    timestamp,
    log_source,
    event_type,
    severity,
    host,
    details
):
    return {
        "timestamp": timestamp,
        "log_source": log_source,
        "event_type": event_type,
        "severity": severity,
        "host": host,
        "details": details
    }