"""
The detector list, in one place.

main.py runs these and test_detectors.py pins what they produce. Keeping two
copies of the list meant the test could silently stop covering a detector the
pipeline was running — which is exactly what happened to container_anomaly.
Adding a detector is now an import and a row, here only.
"""

from detectors.bruteforce import detect_bruteforce
from detectors.service_anomaly import detect_service_anomaly
from detectors.credential_compromise import detect_credential_compromise
from detectors.behavior import detect_behavior
from detectors.session_anomaly import detect_session_anomaly
from detectors.auth_anomaly import detect_auth_anomaly
from detectors.container_anomaly import detect_container_anomaly
from detectors.container_escape import detect_container_escape
from detectors.web_anomaly import detect_web_anomaly
from detectors.privilege_anomaly import detect_privilege_anomaly

DETECTORS = [
    detect_bruteforce,
    detect_service_anomaly,
    detect_credential_compromise,
    detect_behavior,
    detect_session_anomaly,
    detect_auth_anomaly,
    detect_container_anomaly,
    detect_container_escape,
    detect_web_anomaly,
    detect_privilege_anomaly,
]


def run_detectors(events):
    """Every detector over one merged event list, alerts concatenated."""

    alerts = []

    for detect in DETECTORS:
        alerts.extend(detect(events))

    return alerts
