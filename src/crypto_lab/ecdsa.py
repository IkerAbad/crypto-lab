"""ECDSA over secp256k1 with RFC 6979 nonces and low-S normalisation."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .bigint import BigInt, mod_inverse
from .curves import SECP256K1, AffinePoint, Curve
from .encoding import decode_der_signature, encode_der_signature, parse_point
from .hashing import HashFunction, sha256
from .rfc6979 import bits2int, generate_nonces
from .scalarmult import montgomery_ladder


class ECDSAError(ValueError):
    pass


@dataclass(frozen=True)
class Signature:
    r: BigInt
    s: BigInt

    def to_der(self) -> bytes:
        return encode_der_signature(self.r, self.s)

    @classmethod
    def from_der(cls, data: bytes) -> Signature:
        r, s = decode_der_signature(data)
        return cls(r, s)

    def is_malleable(self, order: int | BigInt) -> bool:
        n = order if isinstance(order, BigInt) else BigInt.from_int(order)
        return self.s > n >> 1

    def normalized(self, order: int | BigInt) -> Signature:
        n = order if isinstance(order, BigInt) else BigInt.from_int(order)
        if self.s > n >> 1:
            return Signature(self.r, n - self.s)
        return self


@dataclass(frozen=True)
class PrivateKey:
    curve: Curve
    scalar: BigInt

    def __post_init__(self) -> None:
        if not (BigInt.ZERO < self.scalar < BigInt.from_int(self.curve.n)):
            raise ECDSAError("private scalar is outside [1, n-1]")

    def public_key(self) -> PublicKey:
        point = montgomery_ladder(self.curve, self.scalar, self.curve.g)
        return PublicKey(self.curve, point)


@dataclass(frozen=True)
class PublicKey:
    curve: Curve
    point: AffinePoint

    def __post_init__(self) -> None:
        if self.point.is_infinity or not self.curve.is_on_curve(self.point):
            raise ECDSAError("invalid public key")


def generate_private_key(curve: Curve = SECP256K1) -> PrivateKey:
    """Generate a key with the operating system RNG."""
    scalar = secrets.randbelow(curve.n - 1) + 1
    return PrivateKey(curve, BigInt.from_int(scalar))


def private_key_from_int(value: int, curve: Curve = SECP256K1) -> PrivateKey:
    return PrivateKey(curve, BigInt.from_int(value))


def sign(
    private_key: PrivateKey,
    message: bytes,
    hash_function: HashFunction = sha256,
    low_s: bool = True,
) -> Signature:
    """Deterministic ECDSA (RFC 6979). Low-S is the default."""
    curve = private_key.curve
    order = BigInt.from_int(curve.n)
    digest = hash_function(message)
    z = BigInt.from_int(bits2int(digest, order.bit_length()))

    for k in generate_nonces(private_key.scalar, digest, order, hash_function):
        point = montgomery_ladder(curve, k, curve.g)
        if point.is_infinity:
            continue
        assert point.x is not None
        r = BigInt.from_int(point.x.to_int()) % order
        if not r:
            continue
        s = (mod_inverse(k, order) * (z + r * private_key.scalar)) % order
        if not s:
            continue
        if low_s and s > order >> 1:
            s = order - s
        return Signature(r, s)
    raise ECDSAError("RFC 6979 produced no usable nonce")


def verify(
    public_key: PublicKey,
    message: bytes,
    signature: Signature,
    hash_function: HashFunction = sha256,
    low_s: bool = False,
) -> bool:
    """Verify ECDSA. Set low_s=True to reject malleable high-S signatures."""
    curve = public_key.curve
    order = BigInt.from_int(curve.n)
    if not (BigInt.ZERO < signature.r < order and BigInt.ZERO < signature.s < order):
        return False
    if low_s and signature.s > order >> 1:
        return False

    digest = hash_function(message)
    z = BigInt.from_int(bits2int(digest, order.bit_length()))
    w = mod_inverse(signature.s, order)
    u1 = (z * w) % order
    u2 = (signature.r * w) % order

    point1 = montgomery_ladder(curve, u1, curve.g)
    point2 = montgomery_ladder(curve, u2, public_key.point)
    combined = curve.add_affine(point1, point2)
    if combined.is_infinity:
        return False
    assert combined.x is not None
    return BigInt.from_int(combined.x.to_int()) % order == signature.r


def recover_public_key(
    curve: Curve,
    message: bytes,
    signature: Signature,
    recovery_id: int,
    hash_function: HashFunction = sha256,
) -> PublicKey:
    """Recover the signing public key from a signature and a recovery id.

    recovery_id bit 1 selects the x-coordinate r or r+n; bit 0 selects the
    parity of the ephemeral point R. Values 2 and 3 are usually invalid because
    r+n must still be below the field prime.
    """
    order = BigInt.from_int(curve.n)
    if recovery_id not in (0, 1, 2, 3):
        raise ECDSAError("recovery id must be between 0 and 3")
    if not (BigInt.ZERO < signature.r < order and BigInt.ZERO < signature.s < order):
        raise ECDSAError("signature values are outside [1, n-1]")

    x_value = signature.r.to_int() + (recovery_id >> 1) * curve.n
    if x_value >= curve.p:
        raise ECDSAError("recovery x-coordinate is outside the field")
    prefix = 0x02 | (recovery_id & 1)
    point_r = parse_point(curve, bytes([prefix]) + x_value.to_bytes(32, "big"))

    digest = hash_function(message)
    z = BigInt.from_int(bits2int(digest, order.bit_length()))
    r_inverse = mod_inverse(signature.r, order)
    sr = montgomery_ladder(curve, signature.s, point_r)
    zg = montgomery_ladder(curve, z, curve.g)
    difference = curve.add_affine(sr, curve.negate(zg))
    if difference.is_infinity:
        raise ECDSAError("recovery produced the point at infinity")
    point_q = montgomery_ladder(curve, r_inverse, difference)
    public_key = PublicKey(curve, point_q)
    if not verify(public_key, message, signature, hash_function):
        raise ECDSAError("recovered key does not verify the signature")
    return public_key


def find_recovery_id(
    public_key: PublicKey,
    message: bytes,
    signature: Signature,
    hash_function: HashFunction = sha256,
) -> int | None:
    """Return the recovery id that yields public_key, or None."""
    for candidate in range(4):
        try:
            recovered = recover_public_key(
                public_key.curve, message, signature, candidate, hash_function
            )
        except (ECDSAError, ValueError):
            continue
        if recovered.point == public_key.point:
            return candidate
    return None
