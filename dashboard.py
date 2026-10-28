"""
Build the dashboard from whatever the pipeline and evaluations last produced.

    python3 main.py                  # events, alerts, statistics
    python3 evaluate.py ait/         # outputs/evaluation-ait.json
    python3 dashboard.py             # outputs/dashboard.html

Generated rather than hand-written, and the data is inlined rather than
fetched: a single file opens from disk with no server, no network and no
dependencies. Re-run it after any evaluation and the page is current.

It reads whatever exists and omits the rest, so it works before any evaluation
has been run.
"""

import collections
import glob
import html
import json
import os
from datetime import datetime

OUT = "outputs/dashboard.html"


def load(path, default=None):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def pct(value):
    return "—" if value is None else f"{value:.3f}"


def collect():
    """Everything the page needs, from whatever files are present."""

    events = load("outputs/events.json", [])
    alerts = load("outputs/alerts.json", [])
    stats = load("outputs/statistics.json", {})

    evaluations = []
    for path in sorted(glob.glob("outputs/evaluation-*.json")):
        found = load(path)
        if found:
            found["_name"] = os.path.basename(path)[len("evaluation-"):-len(".json")]
            evaluations.append(found)

    return events, alerts, stats, evaluations


def source_rows(events):
    counts = collections.Counter(e["log_source"] for e in events)
    types = collections.defaultdict(set)

    for event in events:
        types[event["log_source"]].add(event["event_type"])

    return [(source, n, len(types[source])) for source, n in counts.most_common()]


def build():
    events, alerts, stats, evaluations = collect()

    severity = collections.Counter(a["severity"] for a in alerts)
    kinds = collections.Counter(a["alert_type"] for a in alerts)

    doc = [HEAD]

    doc.append(f"""
  <header>
    <h1>Log Parser</h1>
    <p class="sub">Detection engine for a Linux homelab &mdash; five log sources
    normalised into one event stream that eleven detectors read. Pure standard
    library, no dependencies.</p>
    <p class="stamp">generated {datetime.now():%Y-%m-%d %H:%M}</p>
  </header>

  <section class="tiles">
    {tile(len(events), "events parsed")}
    {tile(len(set(e["log_source"] for e in events)), "log sources")}
    {tile(len(set(e["event_type"] for e in events)), "event types")}
    {tile(len(alerts), "alerts")}
    {tile(severity.get("high", 0), "high severity", "high")}
    {tile(severity.get("medium", 0), "medium severity", "medium")}
  </section>""")

    # ---- evaluation results, the part that matters -----------------------
    if evaluations:
        doc.append("<h2>Evaluated against labelled datasets</h2>")
        doc.append("""<p class="sub">Precision is the honest headline: of the
        alerts raised, how many were about a real labelled attack. Recall is
        split so you can see <em>where</em> it is lost &mdash; a labelled line no
        parser consumed is a coverage ceiling needing a parser, a line parsed
        but never cited is a detection miss needing a detector.</p>""")

        doc.append('<div class="table-wrap"><table><thead><tr>'
                   '<th>dataset</th><th class="n">events</th>'
                   '<th class="n">labelled lines</th><th class="n">steps</th>'
                   '<th class="n">step recall</th><th class="n">alerts</th>'
                   '<th class="n">alert precision</th></tr></thead><tbody>')

        for ev in evaluations:
            per_type = ev.get("per_alert_type", {})
            raised = sum(r["alerts"] for r in per_type.values())
            on_attack = sum(r["alerts_on_attack"] for r in per_type.values())
            precision = on_attack / raised if raised else None
            detected = len(ev.get("steps_detected", []))
            total = ev.get("steps_total", 0)

            doc.append(
                f"<tr><td><b>{html.escape(ev['_name'])}</b></td>"
                f"<td class='n'>{ev.get('events', 0):,}</td>"
                f"<td class='n'>{sum(ev.get('labelled_lines', {}).values()):,}</td>"
                f"<td class='n'>{detected}/{total}</td>"
                f"<td class='n'>{pct(ev.get('step_recall'))}</td>"
                f"<td class='n'>{raised:,}</td>"
                f"<td class='n good'>{pct(precision)}</td></tr>")

        doc.append("</tbody></table></div>")

        # per-detector, per-dataset
        doc.append("<h2>Per detector</h2>")
        for ev in evaluations:
            rows = sorted(ev.get("per_alert_type", {}).items(),
                          key=lambda kv: -kv[1]["alerts"])
            if not rows:
                continue
            doc.append(f"<h3>{html.escape(ev['_name'])}</h3>"
                       '<div class="table-wrap"><table><thead><tr><th>detector</th>'
                       '<th class="n">alerts</th><th class="n">on attack</th>'
                       '<th class="n">alert precision</th>'
                       '<th class="n">event precision</th></tr></thead><tbody>')
            for name, row in rows:
                ap = row["alerts_on_attack"] / row["alerts"] if row["alerts"] else None
                epr = (row["attack_events_cited"] / row["events_cited"]
                       if row["events_cited"] else None)
                doc.append(
                    f"<tr><td class='mono'>{html.escape(name)}</td>"
                    f"<td class='n'>{row['alerts']:,}</td>"
                    f"<td class='n'>{row['alerts_on_attack']:,}</td>"
                    f"<td class='n {'good' if ap == 1 else ''}'>{pct(ap)}</td>"
                    f"<td class='n'>{pct(epr)}</td></tr>")
            doc.append("</tbody></table></div>")

        # where recall is lost, per step
        doc.append("<h2>Where recall is lost</h2>")
        doc.append("""<p class="sub">Attack steps with the most labelled lines.
        <strong>coverage</strong> is the fraction a parser consumed;
        <strong>recall</strong> is the fraction of those a detector then cited.
        A coverage of 1.0 with recall 0.0 means the lines were read and nothing
        fired &mdash; that is a detector gap, not a parser one.</p>""")

        for ev in evaluations:
            steps = sorted(ev.get("per_step", {}).items(),
                           key=lambda kv: -kv[1]["labelled"])[:14]
            if not steps:
                continue
            doc.append(f"<h3>{html.escape(ev['_name'])}</h3>"
                       '<div class="table-wrap"><table><thead><tr><th>attack step</th>'
                       '<th class="n">labelled</th><th class="n">parsed</th>'
                       '<th class="n">cited</th><th class="n">coverage</th>'
                       '<th class="n">recall</th></tr></thead><tbody>')
            for name, row in steps:
                hit = row["cited"] > 0
                doc.append(
                    f"<tr class='{'hit' if hit else 'miss'}'>"
                    f"<td class='mono'>{html.escape(name)}</td>"
                    f"<td class='n'>{row['labelled']:,}</td>"
                    f"<td class='n'>{row['parsed']:,}</td>"
                    f"<td class='n'>{row['cited']:,}</td>"
                    f"<td class='n'>{pct(row['coverage'])}</td>"
                    f"<td class='n'>{pct(row['recall'])}</td></tr>")
            doc.append("</tbody></table></div>")

    # ---- the local pipeline ----------------------------------------------
    doc.append("<h2>Sources in the last run</h2>"
               '<div class="table-wrap"><table><thead><tr><th>source</th>'
               '<th class="n">events</th><th class="n">event types</th>'
               '</tr></thead><tbody>')
    for source, count, kinds_n in source_rows(events):
        doc.append(f"<tr><td class='mono'>{html.escape(source)}</td>"
                   f"<td class='n'>{count:,}</td><td class='n'>{kinds_n}</td></tr>")
    doc.append("</tbody></table></div>")

    if alerts:
        doc.append("<h2>Alerts</h2>"
                   '<div class="table-wrap"><table><thead><tr><th>severity</th>'
                   '<th>type</th><th>subject</th><th>recommended action</th>'
                   '</tr></thead><tbody>')
        for alert in sorted(alerts, key=lambda a: (a["severity"] != "high",
                                                   a["alert_type"])):
            subject = (alert.get("source_ip") or alert.get("username")
                       or alert.get("container") or alert.get("service") or "")
            doc.append(
                f"<tr><td><span class='pill {alert['severity']}'>"
                f"{alert['severity']}</span></td>"
                f"<td class='mono'>{html.escape(alert['alert_type'])}</td>"
                f"<td class='mono'>{html.escape(str(subject))}</td>"
                f"<td class='muted'>{html.escape(alert.get('recommended_action',''))}</td>"
                f"</tr>")
        doc.append("</tbody></table></div>")

    doc.append(f"""
  <footer>
    <span>Ankit Bembalgi &middot;
      <a href="https://github.com/AnkitB1405/Linux-Log-Parser">github.com/AnkitB1405/Linux-Log-Parser</a>
    </span>
    <span>{len(kinds)} alert types &middot; {len(evaluations)} evaluation
      {'run' if len(evaluations) == 1 else 'runs'}</span>
  </footer>
</div></body></html>""")

    with open(OUT, "w") as handle:
        handle.write("\n".join(doc))

    print(f"  wrote {OUT}")
    print(f"    {len(events):,} events, {len(alerts)} alerts, "
          f"{len(evaluations)} evaluation run(s)")


def tile(value, label, flavour=""):
    shown = f"{value:,}" if isinstance(value, int) else value

    return (f"<div class='tile {flavour}'><b>{shown}</b>"
            f"<span>{html.escape(label)}</span></div>")


HEAD = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Parser Dashboard</title>
<style>
:root {
  --bg:#fbfaf8; --surface:#fff; --line:#e4e0d8; --ink:#1c1a17;
  --muted:#6b655c; --faint:#9a938a; --high:#b5563a; --medium:#a8792b;
  --good:#2f6f5e; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#15140f; --surface:#1e1c17; --line:#322e26; --ink:#ece7dd;
  --muted:#a39b8f; --faint:#756d61; --high:#e08063; --medium:#d8a94f;
  --good:#5fab94;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:44px 16px 72px}
h1{font-size:clamp(26px,5vw,38px);margin:0 0 8px;letter-spacing:-.02em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint);
  margin:52px 0 14px;font-weight:600}
h3{font-size:14px;margin:22px 0 8px;font-family:var(--mono);color:var(--muted)}
.sub{color:var(--muted);max-width:74ch;margin:0 0 6px}
.stamp{color:var(--faint);font-size:12px;font-family:var(--mono);margin:12px 0 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));
  gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;
  overflow:hidden;margin-top:26px}
.tile{background:var(--surface);padding:15px 17px}
.tile b{display:block;font-size:25px;font-weight:600;letter-spacing:-.02em}
.tile span{font-size:12px;color:var(--muted)}
.tile.high b{color:var(--high)} .tile.medium b{color:var(--medium)}
.table-wrap{background:var(--surface);border:1px solid var(--line);
  border-radius:10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.07em;
  color:var(--faint);font-weight:600;padding:11px 14px;
  border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
.n{text-align:right;font-family:var(--mono);white-space:nowrap}
.mono{font-family:var(--mono);font-size:12.5px}
.muted{color:var(--muted);font-size:12.5px}
.good{color:var(--good);font-weight:600}
tr.miss td{opacity:.62}
tr.hit td:first-child{box-shadow:inset 2px 0 0 var(--good)}
.pill{display:inline-block;font-size:11px;font-family:var(--mono);
  padding:2px 7px;border-radius:4px;border:1px solid currentColor}
.pill.high{color:var(--high)} .pill.medium{color:var(--medium)}
.pill.monitor{color:var(--muted)}
footer{margin-top:60px;padding-top:18px;border-top:1px solid var(--line);
  font-size:12.5px;color:var(--faint);display:flex;flex-wrap:wrap;
  gap:8px 22px;justify-content:space-between}
footer a{color:var(--muted)}
</style></head><body><div class="wrap">"""


if __name__ == "__main__":
    build()
