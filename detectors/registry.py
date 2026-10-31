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
from detectors.post_exploitation import detect_post_exploitation

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
    detect_post_exploitation,
]


# No single detector may drown out the rest. Measured on real production
# auth.log: session_anomaly emitted 318,116 alerts in one run, 98.5% of
# everything the engine said, burying 4,809 correct brute-force alerts. The
# root cause was fixed in that detector, but a detector able to flood at all
# is an architectural gap — any future rule can make the same mistake, and an
# analyst only ever sees the flood.
ALERT_CAP = 50

SEVERITY_RANK = {"high": 0, "medium": 1, "monitor": 2}


def run_detectors(events):
    """Every detector over one merged event list, alerts concatenated."""

    alerts = []

    for detect in DETECTORS:
        alerts.extend(detect(events))

    return rate_limit(alerts)


def rate_limit(alerts, cap=ALERT_CAP):
    """
    Cap alerts per type, replacing the excess with one summary.

    The summary is itself a finding: a rule firing thousands of times means
    either an attack at a scale worth naming, or a rule that is wrong. Both
    are things an analyst needs told, and neither is served by ten thousand
    identical rows.

    Severity ordering decides what survives, so a cap never discards a `high`
    in favour of a `monitor`.
    """

    grouped = {}

    for alert in alerts:
        grouped.setdefault(alert["alert_type"], []).append(alert)

    kept = []

    for kind, group in grouped.items():

        if len(group) <= cap:
            kept.extend(group)
            continue

        group.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 9),
                                  a["timestamp"]))
        kept.extend(group[:cap])

        worst = group[0]
        kept.append({
            "severity": worst["severity"],
            "alert_type": "alert_flood",
            "service": kind,
            "alerts_total": len(group),
            "suppressed": len(group) - cap,
            "timestamp": max(a["timestamp"] for a in group),
            "event_ids": worst.get("event_ids", [])[:20],
            "recommended_action":
            f"{kind} fired {len(group):,} times — confirm an attack at that "
            f"scale, or that the rule is not misfiring",
        })

    return kept
