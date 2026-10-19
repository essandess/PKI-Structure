#!/usr/bin/env python3
"""pki_index.py -- queries on an OpenSSL CA index.txt (parser: pki_validate).

  pki_index.py revoked INDEX                 revoked serials, normalized
  pki_index.py valid INDEX --cn CN [--exclude SERIAL]
                                             valid serials of that CommonName
Normalized: upper case, no leading zeros. `valid` prints serials as in
index.txt, which is the file name under newcerts/.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from pki_validate import index_entries


def main() -> None:
    ap = argparse.ArgumentParser(description="Query an OpenSSL CA index.txt.")
    ap.add_argument("query", choices=("revoked", "valid"))
    ap.add_argument("index")
    ap.add_argument("--cn", help="valid: CommonName to match")
    ap.add_argument("--exclude", default="", help="valid: serial to skip")
    a = ap.parse_args()
    rows = index_entries(Path(a.index))
    if a.query == "revoked":
        for s in sorted({s.lstrip("0").upper() for st, _, s, _ in rows if st == "R"}):
            print(s)
        return
    if a.cn is None:
        ap.error("valid needs --cn")
    skip = int(a.exclude, 16) if a.exclude else None
    for st, _, s, subject in rows:
        m = re.search(r"/CN=([^/]*)", subject)
        if st == "V" and m and m.group(1) == a.cn and int(s, 16) != skip:
            print(s)


if __name__ == "__main__":
    main()
