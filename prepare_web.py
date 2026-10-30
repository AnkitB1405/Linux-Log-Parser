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

import gzip
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


# Which parser each log file should reach, as the suffix evaluate.py routes on.
#
# Matched by pattern rather than exact name, because real deployments name
# these things however they like. Organization X uses `access.log` and
# `web-access.log`; organization Y uses
# `sub17.domain1.com.access_log.2025_04_27` — an UNDERSCORE, a per-vhost
# prefix and a date suffix. An exact-name table missed all 180 of those files.
TARGETS = [
    (re.compile(r"access[._]log"), "access.log"),
    (re.compile(r"error[._]log"), "error.log"),
    (re.compile(r"^auth\.log"), "auth.log"),
    (re.compile(r"^syslog"), "syslog"),
]


def target_for(filename):
    """The route suffix this file should carry, or None to skip it."""

    for pattern, suffix in TARGETS:
        if pattern.search(filename):
            return suffix

    return None


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
            target = target_for(filename)

            if not target:
                continue

            source = os.path.join(directory, filename)

            # The original filename has to be in the flat name. Using only the
            # route target collapsed every rotation and every vhost onto one
            # name — organization X's 58 Apache files became 4, each silently
            # overwriting the last, so only the final file of each type was
            # ever measured.
            flat = f"{name}-{os.path.basename(directory)}-{filename}"

            if not flat.endswith(target):
                flat = f"{flat}.{target}"

            # Rotations are routinely gzipped, and reading one as text yields
            # bytes that match no pattern and inflate the line count with
            # nonsense.
            if filename.endswith(".gz"):
                with gzip.open(source, "rt", errors="replace") as handle:
                    lines = handle.read().splitlines()
            else:
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
