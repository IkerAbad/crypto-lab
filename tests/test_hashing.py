from __future__ import annotations

import json
from pathlib import Path

from crypto_lab.hashing import hmac_sha256, hmac_sha512, ripemd160, sha256, sha512

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"


def test_sha256_vectors() -> None:
    assert sha256(b"").hex() == ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert (
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex()
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    )


def test_sha512_vectors() -> None:
    assert sha512(b"").hex() == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    assert sha512(b"abc").hex() == (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
    assert sha512(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    ).hex() == (
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    )


def test_ripemd160_vectors() -> None:
    vectors = {
        b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        b"a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        b"message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
        b"abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": (
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
        ),
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": (
            "b0e20b6e3116640286ed3a87a5713079b21f5189"
        ),
        b"1234567890" * 8: "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    }
    for message, digest in vectors.items():
        assert ripemd160(message).hex() == digest


def test_long_sha256_message() -> None:
    assert sha256(b"a" * 1_000_000).hex() == (
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )


def test_rfc4231_hmac_vectors() -> None:
    vectors = json.loads((VECTOR_DIR / "rfc4231_hmac_sha256.json").read_text())
    for case in vectors:
        key = bytes.fromhex(case["key"])
        data = bytes.fromhex(case["data"])
        length = case.get("output_bytes")
        expected_sha256 = bytes.fromhex(case["sha256"])
        expected_sha512 = bytes.fromhex(case["sha512"])
        if length is not None:
            expected_sha256 = expected_sha256[:length]
            expected_sha512 = expected_sha512[:length]
        assert hmac_sha256(key, data)[: len(expected_sha256)] == expected_sha256
        assert hmac_sha512(key, data)[: len(expected_sha512)] == expected_sha512


def test_hmac_key_larger_than_block_is_hashed() -> None:
    key = b"k" * 200
    assert hmac_sha256(key, b"message") == hmac_sha256(sha256(key), b"message")


def test_hmac_rejects_nothing_and_is_deterministic() -> None:
    assert hmac_sha256(b"key", b"") == hmac_sha256(b"key", b"")
    assert hmac_sha256(b"key", b"a") != hmac_sha256(b"key", b"b")
