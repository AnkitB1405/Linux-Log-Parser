"""
Work out where this machine keeps its SSH logs.

The parser detects the *format* of a line on its own (see ENVELOPES in
ssh_parser.py). This module answers the other half: which file or command to
read on this particular box, so the pipeline can point itself at the right
input without being told which distro it is running on.

    python3 -m parser.log_source       # report what it found here

Run from the repo root, like the rest of the project.
"""

import os
import platform
import shutil
import subprocess

from parser.ssh_parser import parse_line

AUTH_LOG = "/var/log/auth.log"

JOURNAL_CMD = [
    "journalctl", "-u", "ssh", "-u", "sshd",
    "-o", "short", "--no-pager",
]


def detect_platform():
    """(pretty name, id) from /etc/os-release; ("unknown", "unknown") if absent."""

    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return "unknown", "unknown"

    return release.get("PRETTY_NAME", "unknown"), release.get("ID", "unknown")


def detect_ssh_log():
    """
    Where to read SSH events on this machine, as (kind, target).
    `kind` is "file" or "command"; (None, None) if neither is available.

    Order matters. Mint and Metasploitable both keep /var/log/auth.log and it
    holds the full retained history including rotations, while journald is the
    only source on Kali, which ships no auth.log at all.
    """

    if os.path.isfile(AUTH_LOG) and os.access(AUTH_LOG, os.R_OK):
        return "file", AUTH_LOG

    if shutil.which("journalctl"):
        return "command", JOURNAL_CMD

    return None, None


def read_lines(kind, target):
    """Yield raw log lines from whatever detect_ssh_log() selected."""

    if kind == "file":
        with open(target, errors="replace") as file:
            yield from file

    elif kind == "command":
        result = subprocess.run(target, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            # journalctl interleaves its own markers with the log:
            # "-- Boot 3f2a... --", "-- No entries --". They are not log lines.
            if line.startswith("-- ") and line.endswith(" --"):
                continue
            yield line


if __name__ == "__main__":
    name, distro_id = detect_platform()
    kind, target = detect_ssh_log()

    print(f"platform   {name}  (id={distro_id})")

    if kind is None:
        print("ssh log    none found — no readable /var/log/auth.log, no journalctl")
    else:
        shown = target if kind == "file" else " ".join(target)
        print(f"ssh log    {kind}: {shown}")

        lines = list(read_lines(kind, target))
        print(f"lines      {len(lines)}")

        if lines:
            for line in lines[:400]:
                envelope = parse_line(line)
                if envelope:
                    print(f"format     detected from the line itself")
                    print(f"sample     {line.strip()[:88]}")
                    print(f"parsed as  host={envelope[1]} process={envelope[2]} "
                          f"at {envelope[0]}")
                    break
            else:
                print("format     no envelope matched the first 400 lines")
