"""Rebuilds data/oui.tsv, otinv's built-in MAC vendor list, from the IEEE
registry (MA-L, MA-M, MA-S and the older IAB assignments).

    python scripts/update_oui.py

Run it now and then and commit the result; otinv itself never downloads it.
"""

import csv
import datetime
import io
import pathlib
import sys
import urllib.request

SOURCES = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
    "https://standards-oui.ieee.org/iab/iab.csv",
]
# IEEE's own name on the umbrella blocks it splits into MA-M, MA-S and IAB;
# saying it about a device would be wrong, so those stay unknown
UMBRELLA = "IEEE Registration Authority"
OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "oui.tsv"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "otinv-oui-update"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8")


def main():
    rows = {}
    for url in SOURCES:
        got = 0
        for row in csv.DictReader(io.StringIO(fetch(url))):
            prefix = row["Assignment"].strip().upper()
            name = " ".join(row["Organization Name"].split())
            if prefix and name and name != UMBRELLA:
                rows[prefix] = name
                got += 1
        if got < 1000:
            sys.exit(f"{url} gave only {got} assignments; it looks wrong")
    today = datetime.date.today().isoformat()
    lines = [f"# IEEE Registration Authority MA-L, MA-M, MA-S and IAB, fetched {today}"]
    lines += [f"{p}\t{n}" for p, n in sorted(rows.items())]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {len(rows)} assignments to {OUT}")


if __name__ == "__main__":
    main()
