#!/usr/bin/env python3
"""Analyze a systemd journal for devsec.hardening tuning suggestions.

Accepts:
  - a JSON-lines file from `journalctl -o json`
  - a journal file (`.journal`, `.journal~`, or any path under /var/log/journal)
    — shells out to `journalctl --file=<path> -o json --no-pager`
  - `-` to read JSON lines from stdin

Streams entries, classifies via classifiers.py, samples per class, runs heuristics.
Prints one JSON object to stdout. Stdlib-only.

Usage:
    analyze_journal.py <path-or-->  [--per-class-cap N] [--since "1 day ago"]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classifiers import classify  # noqa: E402
from heuristics import analyze  # noqa: E402


PER_CLASS_CAP_DEFAULT = 50
TOP_SOURCES_PER_CLASS = 10_000  # cap distinct source-IP keys per class


def _is_jsonl(path: str) -> bool:
    """Treat as JSON-lines if first non-empty line parses as JSON object."""
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                return isinstance(obj, dict)
    except (OSError, json.JSONDecodeError):
        return False
    return False


def _iter_jsonl(stream) -> Iterable[dict]:
    for raw in stream:
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except json.JSONDecodeError:
            continue


def _iter_journal_file(path: str, since: str | None) -> Iterable[dict]:
    cmd = ["journalctl", "--file=" + path, "-o", "json", "--no-pager"]
    if since:
        cmd += ["--since", since]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print(json.dumps({"error": "journalctl not found",
                          "hint": "install systemd or pass a JSON-lines file"}))
        sys.exit(2)
    assert proc.stdout is not None
    try:
        yield from _iter_jsonl(proc.stdout)
    finally:
        proc.stdout.close()
        proc.wait()


def _iter_input(path: str, since: str | None) -> Iterable[dict]:
    if path == "-":
        yield from _iter_jsonl(sys.stdin)
        return
    if not os.path.exists(path):
        print(json.dumps({"error": f"file not found: {path}"}))
        sys.exit(2)
    if _is_jsonl(path):
        with open(path, "r", errors="replace") as f:
            yield from _iter_jsonl(f)
    else:
        yield from _iter_journal_file(path, since)


def run(path: str, per_class_cap: int, since: str | None) -> dict:
    counts: Counter[str] = Counter()
    samples: dict[str, list[dict]] = defaultdict(list)
    samples_seen: Counter[str] = Counter()
    top_sources: dict[str, dict[str, int]] = defaultdict(dict)

    for entry in _iter_input(path, since):
        cls, src = classify(entry)
        if cls is None:
            continue
        counts[cls] += 1

        # reservoir sample per class.
        samples_seen[cls] += 1
        bucket = samples[cls]
        if len(bucket) < per_class_cap:
            bucket.append(entry)
        else:
            j = random.randint(0, samples_seen[cls] - 1)
            if j < per_class_cap:
                bucket[j] = entry

        # bounded top-sources tracking.
        if src is not None:
            srcs = top_sources[cls]
            if src in srcs or len(srcs) < TOP_SOURCES_PER_CLASS:
                srcs[src] = srcs.get(src, 0) + 1

    result = analyze(dict(counts), {k: dict(v) for k, v in top_sources.items()})
    result["sample_evidence"] = {
        cls: [e.get("MESSAGE", "")[:200] for e in bucket][:5]
        for cls, bucket in samples.items()
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="JSON-lines file, .journal file, or - for stdin")
    ap.add_argument("--per-class-cap", type=int, default=PER_CLASS_CAP_DEFAULT,
                    help=f"reservoir size per event class (default {PER_CLASS_CAP_DEFAULT})")
    ap.add_argument("--since", default=None,
                    help="passed to journalctl when reading a .journal file")
    args = ap.parse_args()

    result = run(args.path, args.per_class_cap, args.since)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
