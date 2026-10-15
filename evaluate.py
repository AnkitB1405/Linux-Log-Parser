"""
Measure the engine against the AIT Log Data Set's published labels.

    python3 fetch_ait.py get mail.cup.com ait/
    python3 evaluate.py ait/

Every "it works" result before this was circular: the fixtures were written
alongside the parsers, so they agree by construction. AIT ships line-aligned
labels naming which attack step produced each line, which makes it the first
external ground truth this project has had.

WHAT THIS MEASURES, AND WHY IT IS SPLIT THREE WAYS

A single recall number hides the thing you most need to know, so recall is
reported at two stages:

    labelled  ->  parsed  ->  cited by an alert

A labelled attack line that no parser consumed is a *coverage* ceiling — no
detector could ever have caught it, and the fix is a new parser. A line that
was parsed but no alert cited is a *detection* miss, and the fix is a detector.
Conflating them produces one bad number that tells you nothing about what to
do next.

Precision is likewise reported at two levels. Event-level precision (what
fraction of cited events were attack lines) flatters a detector that cites
a thousand events in one alert. Alert-level precision — what fraction of alerts
cited at least one attack line — is what an analyst actually experiences, and
is the honest headline.

METHODOLOGY

This script only measures. It does not tune. Thresholds and windows live in the
detectors, and changing them to improve these numbers and then reporting only
the improved figures is circular validation laundered through a respectable
dataset. Tune against one or two datasets, hold the rest back, and report both.
"""

import collections
import json
import os
import sys
from datetime import datetime

from detectors.registry import run_detectors
from outputs.persistence import save
from parser import auth_parser, envelope, ssh_parser, web_parser

# Which parsers are offered each file. A file may be offered to several: this
# is how the claim that ssh_parser and auth_parser are disjoint gets tested —
# each returns None for the other's lines, and a line claimed twice shows up as
# a duplicate-event error rather than passing silently.
ROUTES = [
    ("auth.log", [ssh_parser.identify_event, auth_parser.identify_event]),
    ("-access.log", [web_parser.identify_event]),
    ("-error.log", [web_parser.identify_event]),
    ("access.log", [web_parser.identify_event]),
    ("error.log", [web_parser.identify_event]),
]

# AIT v1.1 was captured in March 2020. Year-less BSD timestamps have to be
# anchored there, not to today, or every delta spans six years.
CAPTURED = datetime(2020, 3, 6)

BENIGN = {"0", ""}


def parsers_for(name):
    """Every parser offered the given file, longest route match first."""

    for suffix, parsers in sorted(ROUTES, key=lambda r: -len(r[0])):
        if name.endswith(suffix):
            return parsers

    return []


def read_labels(path):
    """
    One label row per log line. `0,0` is benign; anything else names the attack
    step, e.g. `hydra,hydra` or `webshell-netstat-nau,0`.
    """

    rows = []

    for line in open(path, errors="replace"):
        names = {v.strip() for v in line.strip().split(",")} - BENIGN
        rows.append(names)

    return rows


def pair_files(directory):
    """
    (name, data path, label path or None) for every data file present.

    fetch_ait.py flattens paths, so `data/x/auth.log` lands as
    `data-x-auth.log` and its labels as `labels-x-auth.log`.
    """

    found = []

    for entry in sorted(os.listdir(directory)):
        if not entry.startswith("data-"):
            continue

        labels = os.path.join(directory, "labels-" + entry[len("data-"):])
        found.append((
            entry,
            os.path.join(directory, entry),
            labels if os.path.exists(labels) else None,
        ))

    return found


def build(directory):
    """
    Parse every routed file, keeping each event tied to its line's labels.

    Returns (events, truth, coverage) where truth maps event id -> label set
    and coverage counts labelled lines by attack step at each stage.
    """

    envelope.set_reference_time(CAPTURED)

    events = []
    truth = {}
    labelled = collections.Counter()   # attack step -> lines in the data
    parsed = collections.Counter()     # attack step -> lines that became events
    unrouted = collections.Counter()   # file -> labelled lines nothing reads
    claimed_twice = []

    for name, data_path, label_path in pair_files(directory):

        parsers = parsers_for(name)
        labels = read_labels(label_path) if label_path else None

        with open(data_path, errors="replace") as handle:
            for index, line in enumerate(handle):

                line = line.rstrip("\n")

                if not line.strip():
                    continue

                names = labels[index] if labels and index < len(labels) else set()

                for step in names:
                    labelled[step] += 1

                if not parsers:
                    for step in names:
                        unrouted[name] += 1
                    continue

                produced = [e for e in (p(line) for p in parsers) if e]

                if len(produced) > 1:
                    claimed_twice.append((name, line[:90]))

                if produced:
                    event = produced[0]
                    events.append(event)
                    truth[event["id"]] = names

                    for step in names:
                        parsed[step] += 1

    return events, truth, {
        "labelled": labelled,
        "parsed": parsed,
        "unrouted": unrouted,
        "claimed_twice": claimed_twice,
    }


def score(events, truth, alerts):
    """Per-detector and per-attack-step figures from one run."""

    attack_events = {i for i, names in truth.items() if names}

    cited_by_step = collections.Counter()
    per_alert_type = collections.defaultdict(lambda: {
        "alerts": 0, "alerts_on_attack": 0, "events_cited": 0,
        "attack_events_cited": 0, "severity": collections.Counter(),
    })

    cited_events = set()

    for alert in alerts:
        kind = per_alert_type[alert["alert_type"]]
        ids = alert.get("event_ids") or []
        hits = [i for i in ids if i in attack_events]

        kind["alerts"] += 1
        kind["alerts_on_attack"] += 1 if hits else 0
        kind["events_cited"] += len(ids)
        kind["attack_events_cited"] += len(hits)
        kind["severity"][alert["severity"]] += 1

        cited_events.update(ids)

        for i in hits:
            for step in truth[i]:
                cited_by_step[step] += 1

    return {
        "alert_types": {k: dict(v, severity=dict(v["severity"]))
                        for k, v in per_alert_type.items()},
        "cited_by_step": cited_by_step,
        "cited_events": len(cited_events),
        "cited_attack_events": len(cited_events & attack_events),
        "attack_events": len(attack_events),
    }


def ratio(hit, total):
    return round(hit / total, 3) if total else None


def report(events, truth, coverage, alerts, scored):
    """Printed table. The JSON written alongside carries the same figures."""

    bar = "=" * 78
    print(f"\n{bar}\nAIT EVALUATION\n{bar}")

    by_source = collections.Counter(e["log_source"] for e in events)
    print(f"\n  events parsed      {len(events):,}   {dict(by_source)}")
    print(f"  alerts raised      {len(alerts):,}")
    print(f"  labelled lines     {sum(coverage['labelled'].values()):,}")

    if coverage["claimed_twice"]:
        print(f"\n  !! {len(coverage['claimed_twice'])} lines claimed by more than one "
              f"parser — the parsers are not disjoint")
        for name, line in coverage["claimed_twice"][:3]:
            print(f"       {name}: {line}")

    if coverage["unrouted"]:
        print("\n  labelled lines in files NO parser reads (coverage ceiling):")
        for name, count in coverage["unrouted"].most_common():
            print(f"       {count:7,}  {name}")

    # --- recall, split by where it is lost --------------------------------
    print(f"\n  {'attack step':<26} {'labelled':>9} {'parsed':>8} "
          f"{'cited':>7} {'coverage':>9} {'recall':>7}")
    print("  " + "-" * 74)

    for step, total in coverage["labelled"].most_common():
        got_parsed = coverage["parsed"][step]
        cited = scored["cited_by_step"][step]
        print(f"  {step[:26]:<26} {total:>9,} {got_parsed:>8,} {cited:>7,} "
              f"{str(ratio(got_parsed, total)):>9} {str(ratio(cited, got_parsed)):>7}")

    print("\n  coverage = fraction of labelled lines a parser consumed  (fix: parsers)")
    print("  recall   = fraction of those a detector then cited        (fix: detectors)")

    # --- precision, per detector -----------------------------------------
    print(f"\n  {'alert type':<28} {'alerts':>7} {'on attack':>10} "
          f"{'alert prec':>11} {'evt prec':>9}")
    print("  " + "-" * 74)

    for kind, row in sorted(scored["alert_types"].items(),
                            key=lambda kv: -kv[1]["alerts"]):
        print(f"  {kind[:28]:<28} {row['alerts']:>7,} {row['alerts_on_attack']:>10,} "
              f"{str(ratio(row['alerts_on_attack'], row['alerts'])):>11} "
              f"{str(ratio(row['attack_events_cited'], row['events_cited'])):>9}")

    print("\n  alert prec = alerts citing at least one labelled attack line")
    print("               (what an analyst experiences)")
    print("  evt prec   = labelled fraction of all cited events")
    print("               (flattered by one alert citing many events)")

    total_attack = scored["attack_events"]
    print(f"\n{bar}")
    print(f"  overall   attack events parsed: {total_attack:,}   "
          f"cited by an alert: {scored['cited_attack_events']:,}   "
          f"recall {ratio(scored['cited_attack_events'], total_attack)}")
    print(bar)


def main(directory):

    events, truth, coverage = build(directory)

    if not events:
        raise SystemExit(
            f"no events parsed from {directory!r} — run "
            f"`python3 fetch_ait.py get <host> {directory}` first")

    alerts = run_detectors(events)
    scored = score(events, truth, alerts)

    report(events, truth, coverage, alerts, scored)

    save("evaluation", {
        "dataset": "AIT Log Data Set v1.1 (Landauer et al., 2022)",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "events": len(events),
        "events_by_source": dict(collections.Counter(e["log_source"] for e in events)),
        "alerts": len(alerts),
        "labelled_lines": dict(coverage["labelled"]),
        "parsed_lines": dict(coverage["parsed"]),
        "unrouted_lines": dict(coverage["unrouted"]),
        "parsers_not_disjoint": len(coverage["claimed_twice"]),
        "per_step": {
            step: {
                "labelled": total,
                "parsed": coverage["parsed"][step],
                "cited": scored["cited_by_step"][step],
                "coverage": ratio(coverage["parsed"][step], total),
                "recall": ratio(scored["cited_by_step"][step], coverage["parsed"][step]),
            }
            for step, total in coverage["labelled"].items()
        },
        "per_alert_type": scored["alert_types"],
        "overall_recall": ratio(scored["cited_attack_events"], scored["attack_events"]),
    })
    print("\n  written to outputs/evaluation.json")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ait")
