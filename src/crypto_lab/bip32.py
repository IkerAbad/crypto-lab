"""BIP32-style hierarchical key derivation, limited to the master and one child."""

from __future__ import annotations

from dataclasses import dataclass

from .bigint import BigInt
from .curves import SECP256K1, AffinePoint, Curve
from .ecdsa import PublicKey
from .encoding import base58check_encode, serialize_point_compressed
from .hashing import hmac_sha512, ripemd160, sha256
from .scalarmult import montgomery_ladder

HARDENED_OFFSET = 1 << 31
XPRV_VERSION = 0x0488ADE4
XPUB_VERSION = 0x0488B21E


class BIP32Error(ValueError):
    pass


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


@dataclass(frozen=True)
class ExtendedPrivateKey:
    key: BigInt
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0
    curve: Curve = SECP256K1

    def __post_init__(self) -> None:
        if len(self.chain_code) != 32:
            raise BIP32Error("chain code must be 32 bytes")
        if len(self.parent_fingerprint) != 4:
            raise BIP32Error("parent fingerprint must be 4 bytes")
        if not (0 <= self.depth <= 255):
            raise BIP32Error("depth must fit in one byte")
        if not (0 <= self.child_number < 1 << 32):
            raise BIP32Error("child number must fit in four bytes")
        if not (BigInt.ZERO < self.key < BigInt.from_int(self.curve.n)):
            raise BIP32Error("private key is outside the curve order")
        if self.curve.name != "secp256k1":
            raise BIP32Error("BIP32 is defined for secp256k1 in this lab")

    @property
    def public_point(self) -> AffinePoint:
        return montgomery_ladder(self.curve, self.key, self.curve.g)

    def public_key(self) -> PublicKey:
        return PublicKey(self.curve, self.public_point)

    def fingerprint(self) -> bytes:
        return hash160(serialize_point_compressed(self.public_point))[:4]

    def _serialize(self, version: int, key_data: bytes) -> str:
        payload = (
            version.to_bytes(4, "big")
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + key_data
        )
        return base58check_encode(payload)

    def xprv(self) -> str:
        return self._serialize(XPRV_VERSION, b"\x00" + self.key.to_bytes(32))

    def xpub(self) -> str:
        return self._serialize(XPUB_VERSION, serialize_point_compressed(self.public_point))


def master_key_from_seed(seed: bytes, curve: Curve = SECP256K1) -> ExtendedPrivateKey:
    digest = hmac_sha512(b"Bitcoin seed", seed)
    left, right = digest[:32], digest[32:]
    key = BigInt.from_bytes(left)
    if not key or key >= BigInt.from_int(curve.n):
        raise BIP32Error("seed produced an invalid master key")
    return ExtendedPrivateKey(key=key, chain_code=right, curve=curve)


def derive_child(parent: ExtendedPrivateKey, index: int) -> ExtendedPrivateKey:
    if not (0 <= index < 1 << 32):
        raise BIP32Error("child index must fit in four bytes")
    if parent.depth == 255:
        raise BIP32Error("maximum derivation depth reached")
    data = index.to_bytes(4, "big")
    if index >= HARDENED_OFFSET:
        data = b"\x00" + parent.key.to_bytes(32) + data
    else:
        data = serialize_point_compressed(parent.public_point) + data
    digest = hmac_sha512(parent.chain_code, data)
    left, right = digest[:32], digest[32:]
    tweak = BigInt.from_bytes(left)
    order = BigInt.from_int(parent.curve.n)
    if tweak >= order:
        raise BIP32Error("child tweak is outside the curve order")
    child_key = (tweak + parent.key) % order
    if not child_key:
        raise BIP32Error("derived child key is zero")
    return ExtendedPrivateKey(
        key=child_key,
        chain_code=right,
        depth=parent.depth + 1,
        parent_fingerprint=parent.fingerprint(),
        child_number=index,
        curve=parent.curve,
    )
