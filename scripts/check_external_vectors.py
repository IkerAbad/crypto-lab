"""Download official documents and re-check the vendored vectors against them.

Used by the dedicated CI job. It verifies the pinned Wycheproof source hash,
checks that every vendored subset case and public key is identical to its
upstream test object, and runs the complete 476-case secp256k1/SHA-256 corpus.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from crypto_lab.bip32 import HARDENED_OFFSET, derive_child, master_key_from_seed  # noqa: E402
from crypto_lab.curves import P256, SECP256K1  # noqa: E402
from crypto_lab.ecdsa import PublicKey, Signature, private_key_from_int, sign, verify  # noqa: E402
from crypto_lab.encoding import parse_point  # noqa: E402
from crypto_lab.hashing import hmac_sha256  # noqa: E402

RFC4231_URL = "https://www.rfc-editor.org/rfc/rfc4231.txt"
RFC6979_URL = "https://www.rfc-editor.org/rfc/rfc6979.txt"
BIP32_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki"
WYCHEPROOF_PROVENANCE = ROOT / "vectors" / "wycheproof_ecdsa_secp256k1_sha256.provenance.json"


def download(url: str, destination: Path) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "crypto-lab-ci"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    destination.write_bytes(data)
    return data.decode("utf-8")


def check_rfc4231(text: str) -> None:
    compact = "".join(text.split())
    vectors = json.loads((ROOT / "vectors" / "rfc4231_hmac_sha256.json").read_text())
    for case in vectors:
        key = bytes.fromhex(case["key"])
        data = bytes.fromhex(case["data"])
        result = hmac_sha256(key, data).hex()
        length = case.get("output_bytes")
        expected = case["sha256"]
        if length is not None:
            expected = expected[: length * 2]
            result = result[: length * 2]
        if result != expected:
            raise SystemExit(f"RFC 4231 mismatch in {case['name']}")
        if expected not in compact:
            raise SystemExit(f"RFC 4231 output not found in official text: {case['name']}")
    print(f"RFC 4231: {len(vectors)} HMAC-SHA256 vectors verified")


def check_rfc6979(text: str) -> None:
    compact = "".join(text.split())
    vectors = json.loads((ROOT / "vectors" / "rfc6979_p256_sha256.json").read_text())
    private_key = private_key_from_int(int(vectors["private_key"], 16), P256)
    public_key = private_key.public_key()
    assert public_key.point.x is not None and public_key.point.y is not None
    if public_key.point.x.to_int() != int(vectors["public_key"]["x"], 16):
        raise SystemExit("RFC 6979 public x mismatch")
    if public_key.point.y.to_int() != int(vectors["public_key"]["y"], 16):
        raise SystemExit("RFC 6979 public y mismatch")
    for case in vectors["cases"]:
        message = case["message"].encode()
        signature = sign(private_key, message, low_s=False)
        if signature.r.to_bytes(32).hex().upper() != case["r"]:
            raise SystemExit(f"RFC 6979 r mismatch for {case['message']}")
        if signature.s.to_bytes(32).hex().upper() != case["s"]:
            raise SystemExit(f"RFC 6979 s mismatch for {case['message']}")
        for value in (case["k"], case["r"], case["s"]):
            if value not in compact:
                raise SystemExit(f"RFC 6979 value not found in official text: {value}")
        if not verify(public_key, message, signature):
            raise SystemExit(f"RFC 6979 signature does not verify for {case['message']}")
    print(f"RFC 6979: {len(vectors['cases'])} P-256/SHA-256 signatures verified")


def check_bip32(text: str) -> None:
    vectors = json.loads((ROOT / "vectors" / "bip32.json").read_text())
    vector = vectors[0]
    master = master_key_from_seed(bytes.fromhex(vector["seed"]))
    for chain in vector["chains"]:
        key = master if chain["child_index"] is None else derive_child(master, chain["child_index"])
        for field in ("xprv", "xpub"):
            value = getattr(key, field)()
            if value != chain[field]:
                raise SystemExit(f"BIP32 {field} mismatch for {chain['path']}")
            if value not in text:
                raise SystemExit(f"BIP32 {field} not found in official BIP text")
    child = derive_child(master, HARDENED_OFFSET)
    if child.xprv() != vector["chains"][1]["xprv"]:
        raise SystemExit("BIP32 hardened child mismatch")
    print("BIP32: master and first hardened child verified against the BIP text")


def check_wycheproof(path: Path) -> None:
    provenance = json.loads(WYCHEPROOF_PROVENANCE.read_text())
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != provenance["source_sha256"]:
        raise SystemExit(
            f"Wycheproof source hash changed: expected {provenance['source_sha256']}, got {digest}"
        )

    data = json.loads(raw)
    upstream_tests: dict[int, dict[str, object]] = {}
    upstream_keys: dict[int, dict[str, object]] = {}
    for upstream_group in data["testGroups"]:
        for upstream_test in upstream_group["tests"]:
            tc_id = int(upstream_test["tcId"])
            upstream_tests[tc_id] = upstream_test
            upstream_keys[tc_id] = upstream_group["publicKey"]

    subset = json.loads((ROOT / provenance["subset_file"]).read_text())
    subset_cases = 0
    for group in subset["testGroups"]:
        for test in group["tests"]:
            subset_cases += 1
            tc_id = int(test["tcId"])
            if upstream_tests.get(tc_id) != test:
                raise SystemExit(f"vendored Wycheproof test {tc_id} differs upstream")
            if upstream_keys.get(tc_id) != group["publicKey"]:
                raise SystemExit(f"vendored Wycheproof key for test {tc_id} differs upstream")
    if subset_cases != provenance["case_count"]:
        raise SystemExit("vendored Wycheproof case count does not match provenance")

    total = 0
    valid = 0
    invalid = 0
    for group in data["testGroups"]:
        key = group.get("key", group.get("publicKey"))
        public_key = PublicKey(
            SECP256K1, parse_point(SECP256K1, bytes.fromhex(key["uncompressed"]))
        )
        for test in group["tests"]:
            total += 1
            expected = test["result"] == "valid"
            if expected:
                valid += 1
            else:
                invalid += 1
            try:
                signature = Signature.from_der(bytes.fromhex(test["sig"]))
                actual = verify(public_key, bytes.fromhex(test["msg"]), signature)
            except (ValueError, OverflowError):
                actual = False
            if actual is not expected:
                raise SystemExit(f"Wycheproof mismatch at tcId {test['tcId']}")
    if total < 400:
        raise SystemExit("Wycheproof corpus is unexpectedly small")
    print(
        f"Wycheproof: {subset_cases}-case subset matches upstream; "
        f"{total} full cases verified ({valid} valid, {invalid} invalid)"
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="crypto-lab-vectors-") as directory:
        target = Path(directory)
        rfc4231 = download(RFC4231_URL, target / "rfc4231.txt")
        rfc6979 = download(RFC6979_URL, target / "rfc6979.txt")
        bip32 = download(BIP32_URL, target / "bip32.mediawiki")
        wycheproof_path = target / "wycheproof.json"
        provenance = json.loads(WYCHEPROOF_PROVENANCE.read_text())
        download(provenance["source_url"], wycheproof_path)

        check_rfc4231(rfc4231)
        check_rfc6979(rfc6979)
        check_bip32(bip32)
        check_wycheproof(wycheproof_path)
    print("External vector check passed")


if __name__ == "__main__":
    main()
