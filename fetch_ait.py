"""
Pull single files out of the AIT Log Data Set without downloading the archive.

AIT v1.1 is 3.4 GB and v2.0 is roughly 120 GB. Both are served with HTTP range
support, and a zip keeps its file index at the END of the archive — so the
index can be read for a few hundred KB, and any single member fetched by its
recorded offset.

    python3 fetch_ait.py list                      # every file in the archive
    python3 fetch_ait.py get mail.cup.com ait/      # one host's logs and labels

Dataset: Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M.,
& Rauber, A. (2022). Maintainable Log Datasets for Evaluation of Intrusion
Detection Systems. IEEE TDSC. https://zenodo.org/records/4264796

Files land in `ait/`, which is gitignored — the dataset is not ours to
redistribute, and `evaluate.py` expects it there.
"""

import os
import struct
import sys
import urllib.request
import zlib

URL = "https://zenodo.org/records/4264796/files/AIT-LDS-v1_1.zip"


def fetch(start, end):
    request = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def index():
    """Every member as name -> (compression, compressed, uncompressed, offset)."""

    head = urllib.request.Request(URL, method="HEAD")
    with urllib.request.urlopen(head, timeout=60) as response:
        size = int(response.headers["Content-Length"])

    tail = fetch(size - 200_000, size - 1)
    marker = tail.rfind(b"PK\x05\x06")
    directory_size, directory_offset = struct.unpack("<II", tail[marker + 12:marker + 20])
    directory = fetch(directory_offset, directory_offset + directory_size - 1)

    entries, position = {}, 0
    while position < len(directory) - 46:
        if directory[position:position + 4] != b"PK\x01\x02":
            break
        compression, = struct.unpack("<H", directory[position + 10:position + 12])
        compressed, uncompressed = struct.unpack("<II", directory[position + 20:position + 28])
        name_len, extra_len, comment_len = struct.unpack("<HHH", directory[position + 28:position + 34])
        local_offset, = struct.unpack("<I", directory[position + 42:position + 46])
        name = directory[position + 46:position + 46 + name_len].decode("utf-8", "replace")
        entries[name] = (compression, compressed, uncompressed, local_offset)
        position += 46 + name_len + extra_len + comment_len

    return entries


def extract(name, entry, outdir):
    compression, compressed, uncompressed, local_offset = entry

    header = fetch(local_offset, local_offset + 29)
    name_len, extra_len = struct.unpack("<HH", header[26:30])
    start = local_offset + 30 + name_len + extra_len
    payload = fetch(start, start + compressed - 1)

    data = zlib.decompress(payload, -15) if compression == 8 else payload

    # Full path flattened: data/x/auth.log and labels/x/auth.log are different
    # files and must not collide.
    out = os.path.join(outdir, name.strip("/").replace("/", "-"))
    os.makedirs(outdir, exist_ok=True)
    with open(out, "wb") as handle:
        handle.write(data)

    return out, compressed, uncompressed


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "list"
    entries = index()

    if command == "list":
        for name in sorted(entries):
            print(f"  {entries[name][2] / 1e6:8.2f} MB  {name}")

    elif command == "get":
        pattern = sys.argv[2]
        outdir = sys.argv[3] if len(sys.argv) > 3 else "ait"
        hits = sorted(n for n in entries if pattern in n and not n.endswith("/"))

        if not hits:
            sys.exit(f"nothing matching {pattern!r}")

        for name in hits:
            out, compressed, uncompressed = extract(name, entries[name], outdir)
            print(f"  {uncompressed / 1e6:7.2f} MB  {name}")
            print(f"            -> {out}   (fetched {compressed / 1e6:.2f} MB)")
