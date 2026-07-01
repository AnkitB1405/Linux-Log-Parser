from parser.ssh_parser import identify_event
from detectors.bruteforce import detect_bruteforce

events = []

with open("sample_logs/ssh_sample.txt") as file:

    for line in file:

        event = identify_event(line)

        if event:
            events.append(event)

alerts = detect_bruteforce(events)

for alert in alerts:
    print(alert)

'''
for event in events:
    print(event)

print("\nAlerts:\n")

for alert in alerts:
    print(alert)
'''