"""
Turn the Web Server Log Dataset into the aligned form `evaluate.py` reads.

    python3 prepare_web.py web/extract-x/organization-x web/

Unlike AIT, this dataset ships no per-line labels. It ships YAML *rules* — a
list of case-insensitive patterns per attack label, AND-matched, with `%` as a
wildcard — and expects the researcher to apply them.

TWO THINGS TO KNOW BEFORE TRUSTING ANY NUMBER FROM IT

**Some rules do not apply to raw log lines.** The YAML header says the logs are
meant to be processed with log2timeline first, and two of the twenty rules match
on its field names (`code: 404`) rather than on log text. Those are skipped, and
the count of skipped rules is reported.

**The rules that do apply are very coarse.** `rce_shell` is the single pattern
`POST`, so every POST request in the dataset carries an attack label.
`dir_scan` is a common Windows user agent plus `GET` plus `302`. These are
closer to heuristics than to ground truth, and precision computed against them
is not comparable to precision computed against AIT's per-line labels.

So the value of this dataset here is **parse coverage on real production
traffic** — does the parser read logs from actual government web servers — and
not the precision figure. Reported accordingly.
"""

import os
import re
import sys

RULE = re.compile(
    r"- id: (?P<id>\S+)\s*\n"
    r"\s+ground_truth_label: (?P<label>\S+)\s*\n"
    r"\s+sensitivity: (?P<sensitivity>\S+)\s*\n"
    r"\s+filter:\s*\n(?P<filters>(?:\s+- .*\n?)+)"
)

PATTERN = re.compile(r'-\s+"(?P<pattern>.*)"\s*$', re.M)

# A pattern like `code: 404` names a log2timeline field, not log text.
FIELD_PREFIX = re.compile(r"^\s*\w+:\s")


def read_rules(path):
    """(label, [patterns]) for rules that can match raw log text, plus a skip count."""

    text = open(path, errors="replace").read()
    usable, skipped = [], 0

    for found in RULE.finditer(text):
        patterns = [p.strip("%").lower()
                    for p in PATTERN.findall(found["filters"])]

        if any(FIELD_PREFIX.match(p) for p in PATTERN.findall(found["filters"])):
            skipped += 1
            continue

        if patterns:
            usable.append((found["label"], patterns))

    return usable, skipped


def label_for(line, rules):
    """Labels whose every pattern appears in the line. Case-insensitive."""

    lowered = line.lower()

    return {label for label, patterns in rules
            if all(pattern in lowered for pattern in patterns)}


# Which parser each log file should reach, by the name evaluate.py routes on.
TARGETS = {
    "access.log": "access.log",
    "web-access.log": "access.log",
    "other_vhosts_access.log": "access.log",
    "error.log": "error.log",
    "web-error.log": "error.log",
    "auth.log": "auth.log",
}


def prepare(root, outdir):
    name = os.path.basename(root.rstrip("/"))
    truth = os.path.join(root, "ground-truth", f"{name}.yaml")
    rules, skipped = read_rules(truth)

    print(f"  {len(rules)} rules applicable to raw lines, {skipped} skipped "
          f"(they need log2timeline fields)")

    os.makedirs(outdir, exist_ok=True)
    written = 0

    for directory, _dirs, files in os.walk(os.path.join(root, "log")):
        for filename in sorted(files):
            target = TARGETS.get(filename)

            if not target:
                continue

            source = os.path.join(directory, filename)
            flat = f"{name}-{os.path.basename(directory)}-{target}"

            lines = open(source, errors="replace").read().splitlines()

            if not lines:
                continue

            with open(os.path.join(outdir, f"data-{flat}"), "w") as data, \
                 open(os.path.join(outdir, f"labels-{flat}"), "w") as marks:

                for line in lines:
                    found = label_for(line, rules)
                    data.write(line + "\n")
                    marks.write((",".join(sorted(found)) if found else "0") + "\n")

            written += 1
            labelled = sum(1 for line in lines if label_for(line, rules))
            print(f"    {len(lines):>8,} lines, {labelled:>7,} labelled  {flat}")

    print(f"\n  wrote {written} data/label pairs into {outdir}")


if __name__ == "__main__":
    prepare(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "web")
