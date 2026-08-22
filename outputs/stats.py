from collections import Counter

# Seeded so the keys exist even at zero — a dashboard reading this wants a
# stable shape, not a field that vanishes on a quiet day.
SEVERITIES = ("high", "medium", "monitor")


def generate_statistics(events, alerts):

    statistics = {
        "total_events": len(events),
        "total_alerts": len(alerts),
        **{f"{severity}_alerts": 0 for severity in SEVERITIES},
        "services": {},
        "event_types": {}
    }

    # Counted by name rather than an if/elif chain, so a severity that is not
    # listed above still gets a bucket instead of being silently dropped —
    # `monitor` alerts were landing only in total_alerts.
    for alert in alerts:
        key = f"{alert.get('severity') or 'unknown'}_alerts"
        statistics[key] = statistics.get(key, 0) + 1

    statistics["services"] = dict(
        Counter(event.get("log_source") for event in events))
    statistics["event_types"] = dict(
        Counter(event["event_type"] for event in events))

    return statistics
