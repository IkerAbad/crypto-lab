from __future__ import annotations

import json
from pathlib import Path

import pytest

from crypto_lab.bigint import BigInt
from crypto_lab.bip32 import (
    HARDENED_OFFSET,
    XPRV_VERSION,
    XPUB_VERSION,
    BIP32Error,
    derive_child,
    master_key_from_seed,
)
from crypto_lab.encoding import base58check_decode

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"


def test_bip32_vectors() -> None:
    vectors = json.loads((VECTOR_DIR / "bip32.json").read_text())
    for vector in vectors:
        master = master_key_from_seed(bytes.fromhex(vector["seed"]))
        for chain in vector["chains"]:
            index = chain["child_index"]
            key = master if index is None else derive_child(master, index)
            assert key.xprv() == chain["xprv"], (vector["name"], chain["path"])
            assert key.xpub() == chain["xpub"], (vector["name"], chain["path"])


def test_extended_key_layout() -> None:
    master = master_key_from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    private_payload = base58check_decode(master.xprv())
    public_payload = base58check_decode(master.xpub())
    assert len(private_payload) == 78
    assert len(public_payload) == 78
    assert private_payload[:4] == XPRV_VERSION.to_bytes(4, "big")
    assert public_payload[:4] == XPUB_VERSION.to_bytes(4, "big")
    assert private_payload[4] == 0
    assert public_payload[4] == 0
    assert private_payload[5:9] == b"\x00\x00\x00\x00"
    assert public_payload[5:9] == b"\x00\x00\x00\x00"
    assert private_payload[9:13] == b"\x00\x00\x00\x00"
    assert public_payload[9:13] == b"\x00\x00\x00\x00"
    assert private_payload[13:45] == public_payload[13:45]
    assert private_payload[45] == 0
    assert public_payload[45] in (2, 3)


def test_hardened_and_non_hardened_children_differ() -> None:
    master = master_key_from_seed(b"seed")
    hardened = derive_child(master, HARDENED_OFFSET)
    normal = derive_child(master, 0)
    assert hardened.key != normal.key
    assert hardened.chain_code != normal.chain_code
    assert hardened.parent_fingerprint == normal.parent_fingerprint


def test_derived_key_is_valid() -> None:
    master = master_key_from_seed(b"another seed")
    child = derive_child(master, 1)
    assert BigInt.ZERO < child.key < BigInt.from_int(master.curve.n)
    assert child.depth == 1
    assert child.parent_fingerprint == master.fingerprint()


def test_invalid_child_index() -> None:
    master = master_key_from_seed(b"seed")
    with pytest.raises(BIP32Error):
        derive_child(master, 1 << 32)
    with pytest.raises(BIP32Error):
        derive_child(master, -1)
