"""Downloads the public captures listed in tests/public-traces.txt.

    python scripts/fetch_public_traces.py target/public-traces

Each file is checked against its SHA-256 before it's kept. Files already
there with the right hash aren't downloaded again.
"""

import hashlib
import pathlib
import sys
import urllib.request

LIST = pathlib.Path(__file__).resolve().parent.parent / "tests" / "public-traces.txt"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main(out):
    out.mkdir(parents=True, exist_ok=True)
    for line in LIST.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, want, url = line.split()
        path = out / name
        if path.is_file() and sha256(path.read_bytes()) == want:
            continue
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        got = sha256(data)
        if got != want:
            sys.exit(f"{name}: SHA-256 is {got}, expected {want} ({url})")
        path.write_bytes(data)
        print(f"fetched {name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(pathlib.Path(sys.argv[1]))
