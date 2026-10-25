"""
Cut a measurable slice out of AIT's audit log.

    python3 slice_audit.py mail.spiral.com

One host's audit.log is 59,522,342 lines and 4.3 GB inflated, with 1,464,885
of those lines labelled. Neither the evaluation harness nor this machine can
hold that, so this reduces it to the part worth measuring and writes an aligned
data/label pair that `evaluate.py` reads like any other AIT file.

TWO THINGS THIS HAS TO GET RIGHT

**Complete groups.** An audit event spans several lines joined by
msg=audit(epoch:serial). Keeping only the labelled lines would shear events in
half and the parser would see fragments. So the unit of selection is the
*group*: if any line of a group is labelled, every line of it is kept.

**Benign context.** A slice containing nothing but attack traffic can only
measure recall — precision would be meaningless, since there would be nothing
for a detector to be wrong about. Every Nth benign group is kept so the
false-positive rate stays measurable.

Streams both the data and its labels in lockstep and never holds either in
memory. Labels come from a separate 0.5 MB zip whose rows are aligned one-to-one
with the data's lines, so the two have to advance together.
"""

import io
import re
import sys
import zipfile
import zlib

import fetch_ait

# Attack steps already measured through other parsers. Keeping their labelled
# lines would add millions of rows and tell us nothing new — nikto alone is
# 1,198,999 of them, and it is already detected at the web layer.
ALREADY_MEASURED = {"nikto", "hydra"}

# One benign group kept per this many, for precision.
BENIGN_SAMPLE = 400

# A group is considered finished once this many lines have passed without
# another record joining it. Records of one event are adjacent in practice.
GROUP_LOOKBEHIND = 200

STAMP = re.compile(r"msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")
BENIGN = {"0", ""}


def label_lines(host):
    """Stream the label rows for a host's audit.log."""

    entry = fetch_ait.index()[f"labels/{host}/audit/audit.zip"]
    inner = fetch_ait.nested_index(entry)["audit.log"]
    method, compressed, _usize, _local = inner

    base = fetch_ait.data_offset(inner)
    stream = zlib.decompressobj(-15) if method == 8 else None
    carry = ""
    done = 0

    while done < compressed:
        size = min(8_000_000, compressed - done)
        raw = fetch_ait.fetch(base + done, base + done + size - 1)
        done += size

        text = (stream.decompress(raw) if stream else raw).decode("utf-8", "replace")
        carry += text
        *ready, carry = carry.split("\n")

        yield from ready

    if carry:
        yield carry


def data_lines(path):
    """Stream audit.log out of a locally saved audit.zip, never inflating it all."""

    with zipfile.ZipFile(path) as archive:
        with archive.open("audit.log") as handle:
            for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                yield line.rstrip("\n")


def wanted(labels):
    """True when a group's labels name a step not already measured elsewhere."""

    return any(name not in ALREADY_MEASURED for name in labels)


def slice_host(host, archive, out_data, out_labels):

    groups = {}          # serial -> [last_seen, [lines], set(labels)]
    kept_groups = 0
    kept_lines = 0
    benign_seen = 0
    seen = 0

    data = open(out_data, "w")
    marks = open(out_labels, "w")

    def flush(serial):
        nonlocal kept_groups, kept_lines, benign_seen

        _last, lines, labels = groups.pop(serial)
        attack = wanted(labels)

        if not attack:
            benign_seen += 1
            if benign_seen % BENIGN_SAMPLE:
                return

        for line in lines:
            data.write(line + "\n")
            marks.write((",".join(sorted(labels)) if attack else "0") + "\n")
            kept_lines += 1

        kept_groups += 1

    for seen, (line, label) in enumerate(zip(data_lines(archive), label_lines(host)), 1):

        stamp = STAMP.search(line)

        if stamp:
            serial = stamp["serial"]
            names = {v.strip() for v in label.split(",")} - BENIGN
            slot = groups.setdefault(serial, [seen, [], set()])
            slot[0] = seen
            slot[1].append(line)
            slot[2] |= names

        if seen % 50_000 == 0:
            for serial in [s for s, v in groups.items()
                           if seen - v[0] > GROUP_LOOKBEHIND]:
                flush(serial)

        if seen % 5_000_000 == 0:
            print(f"    {seen:,} lines read, {kept_groups:,} groups kept", flush=True)

    for serial in list(groups):
        flush(serial)

    data.close()
    marks.close()

    print(f"\n  read   {seen:,} lines")
    print(f"  kept   {kept_lines:,} lines in {kept_groups:,} complete groups")
    print(f"  wrote  {out_data}")
    print(f"         {out_labels}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "mail.spiral.com"
    slice_host(
        host,
        f"ait/audit-{host}.zip",
        f"ait/data-{host}-audit-audit.log",
        f"ait/labels-{host}-audit-audit.log",
    )
