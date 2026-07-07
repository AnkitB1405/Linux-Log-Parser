import json
from datetime import datetime

def json_serializer(obj):

    if isinstance(obj, datetime):
        return obj.isoformat()

    raise TypeError(
        f"{type(obj)} is not JSON serializable"
    )

def save_events(events):

    with open(
        "outputs/events.json",
        "w"
    ) as file:

        json.dump(
            events,
            file,
            indent=4,
            default=json_serializer
        )

def save_alerts(alerts):

    with open(
        "outputs/alerts.json",
        "w"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4,
            default=json_serializer
        )

def save_statistics(statistics):

    with open(
        "outputs/statistics.json",
        "w"
    ) as file:

        json.dump(
            statistics,
            file,
            indent=4
        )