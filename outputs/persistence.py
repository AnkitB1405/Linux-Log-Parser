import json
from datetime import datetime


def save(name, data):
    """Write outputs/<name>.json. Datetimes are written as ISO strings."""

    with open(f"outputs/{name}.json", "w") as file:
        json.dump(data, file, indent=4, default=encode)


def encode(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()

    raise TypeError(f"{type(obj)} is not JSON serializable")
