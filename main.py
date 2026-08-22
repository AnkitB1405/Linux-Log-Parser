import sys

from parser.ssh_parser import identify_event as parse_ssh
from parser.docker_parser import identify_event as parse_docker
from parser.log_source import detect_platform, detect_ssh_log, read_lines

from detectors.registry import DETECTORS

from outputs.persistence import *
from outputs.stats import generate_statistics

SSH_DATASET = "sample_logs/ssh_dataset_v1.txt"
DOCKER_DATASET = "sample_logs/docker_events_v1.jsonl"

def sources():
    """
    (label, lines, parser) for every log this run should read.

    `--live` swaps the SSH fixture for whatever this machine actually keeps,
    detected at runtime. Docker always reads the captured fixture: Docker holds
    its event log in memory and loses it on daemon restart, so a live path
    needs a collector writing that file continuously — not built yet.
    """

    if "--live" in sys.argv:
        platform, _ = detect_platform()
        kind, target = detect_ssh_log()

        if kind is None:
            raise SystemExit(f"no readable SSH log found on {platform}")

        print(f"reading live SSH log on {platform}")
        yield "ssh", list(read_lines(kind, target)), parse_ssh

    else:
        with open(SSH_DATASET) as file:
            yield "ssh", file.readlines(), parse_ssh

    with open(DOCKER_DATASET) as file:
        yield "docker", file.readlines(), parse_docker


def collect_events():
    """Parse every source into one normalized event list."""

    events = []
    errors = []

    for label, lines, parse in sources():
        parsed = 0

        for line in lines:
            try:
                event = parse(line)

                if event:
                    events.append(event)
                    parsed += 1

            except Exception as e:
                errors.append({
                    "source": label,
                    "line": line.strip(),
                    "error": str(e)
                })

        print(f"  {label:<8} {parsed} events from {len(lines)} lines")

    return events, errors


print("\nSources:\n")
events, errors = collect_events()

all_alerts = []

print("\nAlerts:\n")

# Every detector filters by event_type, so each only sees the events it cares
# about and sources can be merged freely.
for detect in DETECTORS:
    for alert in detect(events):
        print(alert)
        all_alerts.append(alert)

statistics = generate_statistics(events, all_alerts)

save_events(events)
save_alerts(all_alerts)
save_statistics(statistics)

print("\nErrors\n")

for error in errors:
    print(error)
