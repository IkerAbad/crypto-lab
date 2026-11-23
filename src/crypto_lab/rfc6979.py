"""RFC 6979 deterministic nonce generation for ECDSA."""

from __future__ import annotations

from collections.abc import Iterator

from .bigint import BigInt
from .hashing import HashFunction, hmac, sha256


def bits2int(data: bytes, qlen: int) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    if excess > 0:
        value >>= excess
    return value


def int2octets(value: int, rlen: int) -> bytes:
    return value.to_bytes(rlen, "big")


def bits2octets(data: bytes, order: int, qlen: int, rlen: int) -> bytes:
    z1 = bits2int(data, qlen)
    z2 = z1 - order if z1 >= order else z1
    return int2octets(z2, rlen)


def generate_nonces(
    private_key: int | BigInt,
    digest: bytes,
    order: int | BigInt,
    hash_function: HashFunction = sha256,
    block_size: int = 64,
) -> Iterator[BigInt]:
    """Yield RFC 6979 candidate nonces in order."""
    d = private_key.to_int() if isinstance(private_key, BigInt) else private_key
    q = order.to_int() if isinstance(order, BigInt) else order
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    hlen = len(hash_function(b""))
    x = int2octets(d, rlen)
    h1 = bits2octets(digest, q, qlen, rlen)

    v = b"\x01" * hlen
    k = b"\x00" * hlen
    k = hmac(hash_function, block_size, k, v + b"\x00" + x + h1)
    v = hmac(hash_function, block_size, k, v)
    k = hmac(hash_function, block_size, k, v + b"\x01" + x + h1)
    v = hmac(hash_function, block_size, k, v)

    while True:
        t = b""
        while len(t) < rlen:
            v = hmac(hash_function, block_size, k, v)
            t += v
        candidate = bits2int(t, qlen)
        if 1 <= candidate < q:
            yield BigInt.from_int(candidate)
        k = hmac(hash_function, block_size, k, v + b"\x00")
        v = hmac(hash_function, block_size, k, v)
