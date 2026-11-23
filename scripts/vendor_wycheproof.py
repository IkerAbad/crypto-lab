"""Vendor a representative Wycheproof ECDSA secp256k1/SHA-256 subset.

The script pins the hash of the upstream file. If upstream changes, the hash
check fails on purpose and a human must review the new vectors before updating
``SOURCE_SHA256`` and the provenance file.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_URL = (
    "https://raw.githubusercontent.com/C2SP/wycheproof/master/"
    "testvectors_v1/ecdsa_secp256k1_sha256_test.json"
)
SOURCE_SHA256 = "43db761c0a2eae71fb0755d355d5130e28ce64a5b07846cf27e7072082597a81"
SUBSET_PATH = ROOT / "vectors" / "wycheproof_ecdsa_secp256k1_sha256.json"
PROVENANCE_PATH = ROOT / "vectors" / "wycheproof_ecdsa_secp256k1_sha256.provenance.json"
FETCHED_AT = "2026-11-23"
SELECTION = (
    "Every Wycheproof flag combination is represented. Combinations with at most "
    "10 tests are included whole; larger combinations contribute three evenly spaced "
    "tests. ArithmeticError contributes both valid and invalid cases, and all "
    "ValidSignature, PointDuplication, RangeCheck, IntegerOverflow, ModifiedInteger, "
    "BerEncodedSignature and SmallRandS tests are kept."
)


def download() -> bytes:
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "crypto-lab-vendor"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def choose_ids(data: dict[str, object]) -> set[int]:
    by_flags: dict[tuple[str, ...], list[dict[str, object]]] = collections.defaultdict(list)
    for group in data["testGroups"]:  # type: ignore[union-attr]
        for test in group["tests"]:
            by_flags[tuple(sorted(test.get("flags", [])))].append(test)

    selected: set[int] = set()
    for flags, tests in by_flags.items():
        if len(tests) <= 10:
            selected.update(int(test["tcId"]) for test in tests)
        elif flags == ("ArithmeticError",):
            valid = [test for test in tests if test["result"] == "valid"]
            invalid = [test for test in tests if test["result"] == "invalid"]
            for group in (valid, invalid):
                if group:
                    selected.add(int(group[0]["tcId"]))
                    selected.add(int(group[len(group) // 2]["tcId"]))
                    selected.add(int(group[-1]["tcId"]))
        else:
            selected.add(int(tests[0]["tcId"]))
            selected.add(int(tests[len(tests) // 2]["tcId"]))
            selected.add(int(tests[-1]["tcId"]))
    selected.update(int(test["tcId"]) for test in by_flags[("ValidSignature",)])
    return selected


def build_subset(data: dict[str, object], selected: set[int]) -> dict[str, object]:
    groups: list[dict[str, object]] = []
    valid = 0
    invalid = 0
    for group in data["testGroups"]:  # type: ignore[union-attr]
        tests = [test for test in group["tests"] if int(test["tcId"]) in selected]
        if not tests:
            continue
        for test in tests:
            if test["result"] == "valid":
                valid += 1
            else:
                invalid += 1
        groups.append(
            {
                "type": group.get("type", "EcdsaVerify"),
                "publicKey": group["publicKey"],
                "sha": group.get("sha", "SHA-256"),
                "tests": tests,
            }
        )
    return {
        "algorithm": data.get("algorithm", "ECDSA"),
        "schema": data.get("schema", "ecdsa_test_schema.json"),
        "source": "Wycheproof ecdsa_secp256k1_sha256_test.json",
        "source_url": SOURCE_URL,
        "source_sha256": SOURCE_SHA256,
        "selection": SELECTION,
        "case_count": valid + invalid,
        "valid_count": valid,
        "invalid_count": invalid,
        "testGroups": groups,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that the committed subset matches a fresh download",
    )
    args = parser.parse_args()

    raw = download()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCE_SHA256:
        raise SystemExit(
            "upstream Wycheproof SHA-256 changed: "
            f"expected {SOURCE_SHA256}, got {digest}. Review the diff before updating."
        )
    data = json.loads(raw)
    selected = choose_ids(data)
    subset = build_subset(data, selected)
    subset_bytes = (json.dumps(subset, indent=2) + "\n").encode()
    subset_sha256 = hashlib.sha256(subset_bytes).hexdigest()

    provenance = {
        "source": subset["source"],
        "source_url": SOURCE_URL,
        "fetched_at": FETCHED_AT,
        "source_sha256": SOURCE_SHA256,
        "subset_file": SUBSET_PATH.relative_to(ROOT).as_posix(),
        "subset_sha256": subset_sha256,
        "case_count": subset["case_count"],
        "valid_count": subset["valid_count"],
        "invalid_count": subset["invalid_count"],
        "selection": SELECTION,
        "notes": "tcIds and test objects are copied unchanged from the upstream file.",
    }
    provenance_bytes = (json.dumps(provenance, indent=2) + "\n").encode()

    if args.check:
        if not SUBSET_PATH.exists() or SUBSET_PATH.read_bytes() != subset_bytes:
            raise SystemExit("committed Wycheproof subset differs from a fresh download")
        if not PROVENANCE_PATH.exists() or PROVENANCE_PATH.read_bytes() != provenance_bytes:
            raise SystemExit("committed Wycheproof provenance differs from a fresh download")
        print(
            f"Wycheproof subset OK: {subset['case_count']} cases "
            f"({subset['valid_count']} valid, {subset['invalid_count']} invalid), "
            f"sha256 {subset_sha256}"
        )
        return

    SUBSET_PATH.write_bytes(subset_bytes)
    PROVENANCE_PATH.write_bytes(provenance_bytes)
    print(
        f"wrote {SUBSET_PATH.relative_to(ROOT)}: {subset['case_count']} cases "
        f"({subset['valid_count']} valid, {subset['invalid_count']} invalid), "
        f"sha256 {subset_sha256}"
    )
    print(f"wrote {PROVENANCE_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
