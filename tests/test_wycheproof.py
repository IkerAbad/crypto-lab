from __future__ import annotations

import hashlib
import json
from pathlib import Path

from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import PublicKey, Signature, verify
from crypto_lab.encoding import parse_point

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"
SUBSET_PATH = VECTOR_DIR / "wycheproof_ecdsa_secp256k1_sha256.json"
PROVENANCE_PATH = VECTOR_DIR / "wycheproof_ecdsa_secp256k1_sha256.provenance.json"


def _load() -> tuple[dict[str, object], dict[str, object]]:
    subset = json.loads(SUBSET_PATH.read_text())
    provenance = json.loads(PROVENANCE_PATH.read_text())
    return subset, provenance


def test_wycheproof_provenance_and_hash() -> None:
    subset, provenance = _load()
    assert hashlib.sha256(SUBSET_PATH.read_bytes()).hexdigest() == provenance["subset_sha256"]
    assert provenance["subset_file"] == "vectors/wycheproof_ecdsa_secp256k1_sha256.json"
    assert subset["source_sha256"] == provenance["source_sha256"]
    assert provenance["source"] == "Wycheproof ecdsa_secp256k1_sha256_test.json"

    tests = [test for group in subset["testGroups"] for test in group["tests"]]
    flags = {tuple(sorted(test.get("flags", []))) for test in tests}
    assert len(tests) == subset["case_count"] == provenance["case_count"]
    assert sum(test["result"] == "valid" for test in tests) == provenance["valid_count"]
    assert sum(test["result"] == "invalid" for test in tests) == provenance["invalid_count"]
    assert len(flags) == 18
    assert len(tests) >= 60


def test_wycheproof_secp256k1_sha256_subset() -> None:
    subset, provenance = _load()
    total = 0
    for group in subset["testGroups"]:
        key = group.get("key", group.get("publicKey"))
        point = parse_point(SECP256K1, bytes.fromhex(key["uncompressed"]))
        public_key = PublicKey(SECP256K1, point)
        for test in group["tests"]:
            total += 1
            expected = test["result"]
            assert expected in ("valid", "invalid")
            try:
                signature = Signature.from_der(bytes.fromhex(test["sig"]))
                actual = verify(public_key, bytes.fromhex(test["msg"]), signature)
            except (ValueError, OverflowError):
                actual = False
            assert actual is (expected == "valid"), test["tcId"]
    assert total == provenance["case_count"]
