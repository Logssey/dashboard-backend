"""Fail a synthetic regression if known fixture tokens escape into text artifacts.

The needle file must contain synthetic values only, one UTF-8 value per line.
Neither token contents nor matching artifact names are printed.
"""
import argparse
import json
from pathlib import Path
import sys


def contains_needle(path: Path, needles: list[bytes]) -> bool:
    overlap = max(map(len, needles)) - 1
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            window = tail + chunk
            if any(needle in window for needle in needles):
                return True
            tail = window[-overlap:] if overlap else b""
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--needles-file", required=True, type=Path)
    parser.add_argument("--input", required=True, action="append", type=Path)
    args = parser.parse_args()
    try:
        raw = args.needles_file.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ValueError()
        needles = [line.encode("utf-8") for line in raw.decode("utf-8").splitlines() if line]
        if not needles or any(not 16 <= len(value) <= 4096 for value in needles):
            raise ValueError()
        leaking = sum(contains_needle(path, needles) for path in args.input)
    except (OSError, UnicodeError, ValueError):
        print('{"status":"INVALID_INPUT"}')
        return 2
    print(json.dumps({"status": "FAILED" if leaking else "PASSED",
                      "checkedInputs": len(args.input), "leakingInputs": leaking}))
    return 1 if leaking else 0


if __name__ == "__main__":
    sys.exit(main())
