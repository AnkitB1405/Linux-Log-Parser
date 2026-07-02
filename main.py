from parser.ssh_parser import identify_event
from detectors.bruteforce import detect_bruteforce
from detectors.service_anomaly import detect_service_anomaly
from detectors.credential_compromise import detect_credential_compromise
from detectors.behavior import detect_behavior
from detectors.session_anomaly import detect_session_anomaly

events = []
errors = []

with open("sample_logs/ssh_sample.txt") as file:

    for line in file:

        try:
            event = identify_event(line)

            if event:
                events.append(event)

        except Exception as e:

            errors.append({
                "line": line.strip(),
                "error": str(e)
            })

print("\nAlerts:\n")

alerts = detect_bruteforce(events)
for alert in alerts:
    print(alert)

service_alerts = detect_service_anomaly(events)
for alert in service_alerts:
    print(alert)

credential_alerts = detect_credential_compromise(events)
for alert in credential_alerts:
    print(alert)

behavior_alerts = detect_behavior(events)
for alert in behavior_alerts:
    print(alert)

session_alerts = detect_session_anomaly(events)
for alert in session_alerts:
    print(alert)

'''
for event in events:
    print(event)
'''

print("\nErrors\n")

for error in errors:

    print(error)