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

# v1.1 by default; set_archive() points the same range-request machinery at
# another Zenodo zip — v2.1 ships per-host archives, and the *_no-pcaps
# variants are 688 MB instead of 16 GB because they leave out packet captures.
URL = "https://zenodo.org/records/4264796/files/AIT-LDS-v1_1.zip"

ARCHIVES = {
    "v1.1": "https://zenodo.org/records/4264796/files/AIT-LDS-v1_1.zip",
    "v2.1-fox": "https://zenodo.org/records/19483937/files/fox_no-pcaps.zip",
    "v2.1-harrison": "https://zenodo.org/records/19483937/files/harrison_no-pcaps.zip",
    "v2.1-shaw": "https://zenodo.org/records/19483937/files/shaw_no-pcaps.zip",
}


def set_archive(name):
    """Point every fetch at a different archive, by key or full URL."""

    global URL
    URL = ARCHIVES.get(name, name)

    return URL


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


def data_offset(entry):
    """Absolute offset of a member's payload, past its local header."""

    _method, _compressed, _uncompressed, local_offset = entry
    header = fetch(local_offset, local_offset + 29)
    name_len, extra_len = struct.unpack("<HH", header[26:30])

    return local_offset + 30 + name_len + extra_len


def nested_index(entry):
    """
    Index a zip that is STORED inside the archive, without downloading it.

    AIT keeps each host's auditd logs in an audit.zip of 542 MB to 1.1 GB. The
    outer archive stores those uncompressed (method 0), so their bytes sit
    contiguously at a known offset and the same end-of-central-directory walk
    works one level down. Inner member offsets are relative to the inner zip's
    first byte, so adding that base makes them absolute in the outer file — and
    a single member can then be range-requested like any other.
    """

    method, compressed, _uncompressed, _local = entry

    if method != 0:
        raise ValueError("nested zip is deflated, not stored - cannot seek into it")

    base = data_offset(entry)
    tail = fetch(base + compressed - 200_000, base + compressed - 1)
    marker = tail.rfind(b"PK\x05\x06")
    directory_size, directory_offset = struct.unpack("<II", tail[marker + 12:marker + 20])
    blob = fetch(base + directory_offset,
                 base + directory_offset + directory_size - 1)

    entries, position = {}, 0

    while position < len(blob) - 46:
        if blob[position:position + 4] != b"PK\x01\x02":
            break
        compression, = struct.unpack("<H", blob[position + 10:position + 12])
        csize, usize = struct.unpack("<II", blob[position + 20:position + 28])
        name_len, extra_len, comment_len = struct.unpack(
            "<HHH", blob[position + 28:position + 34])
        local, = struct.unpack("<I", blob[position + 42:position + 46])
        name = blob[position + 46:position + 46 + name_len].decode("utf-8", "replace")
        entries[name] = (compression, csize, usize, base + local)
        position += 46 + name_len + extra_len + comment_len

    return entries


def head(entry, megabytes=8):
    """
    Inflate the first few MB of a deflated member without fetching all of it.

    AIT's audit.log is a single 4.3 GB deflate stream compressed to 542 MB.
    Nothing can seek into it — but a prefix of the stream inflates fine, which
    is enough to learn the record format and sample real lines. Reaching a
    specific point in time means streaming the whole thing; that is a separate,
    much heavier operation.
    """

    method, compressed, _uncompressed, _local = entry

    if method != 8:
        raise ValueError("member is not deflated")

    base = data_offset(entry)
    want = min(int(megabytes * 1e6), compressed)
    raw = fetch(base, base + want - 1)

    stream = zlib.decompressobj(-15)
    out = stream.decompress(raw)

    return out.decode("utf-8", "replace"), want


def save_stored(entry, path, chunk_mb=16):
    """
    Write a STORED member to disk in chunks, never holding it in memory.

    Used for the nested audit.zip: because the outer archive stores it
    uncompressed, copying its byte range out produces a valid standalone zip.
    542 MB to 1.1 GB per host, so this is a deliberate one-time download rather
    than something to repeat.
    """

    method, compressed, _uncompressed, _local = entry

    if method != 0:
        raise ValueError("member is deflated; use head() or extract() instead")

    base = data_offset(entry)
    step = int(chunk_mb * 1e6)
    done = 0

    with open(path, "wb") as handle:
        while done < compressed:
            size = min(step, compressed - done)
            handle.write(fetch(base + done, base + done + size - 1))
            done += size
            print(f"    {done / 1e6:7.0f} / {compressed / 1e6:.0f} MB", flush=True)

    return path


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
