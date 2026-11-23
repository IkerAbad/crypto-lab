from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import PublicKey, Signature, verify
from crypto_lab.encoding import parse_point

WYCHEPROOF_PATH = os.environ.get("WYCHEPROOF_ECDSA_SECP256K1")
pytestmark = pytest.mark.skipif(
    not WYCHEPROOF_PATH or not Path(WYCHEPROOF_PATH).exists(),
    reason="set WYCHEPROOF_ECDSA_SECP256K1 to run external Wycheproof vectors",
)


def test_wycheproof_secp256k1_sha256() -> None:
    assert WYCHEPROOF_PATH is not None
    data = json.loads(Path(WYCHEPROOF_PATH).read_text())
    assert data["algorithm"] == "ECDSA"
    total = 0
    for group in data["testGroups"]:
        key = group.get("key", group.get("publicKey"))
        uncompressed = bytes.fromhex(key["uncompressed"])
        public_key = PublicKey(SECP256K1, parse_point(SECP256K1, uncompressed))
        for test in group["tests"]:
            total += 1
            expected = test["result"]
            if expected == "acceptable":
                continue
            try:
                signature = Signature.from_der(bytes.fromhex(test["sig"]))
                actual = verify(public_key, bytes.fromhex(test["msg"]), signature)
            except (ValueError, OverflowError):
                actual = False
            assert actual is (expected == "valid"), test["tcId"]
    assert total >= 400
