"""SEC1 point encoding, DER signatures, PEM keys and Base58Check."""

from __future__ import annotations

import base64

from .bigint import BigInt
from .curves import AffinePoint, Curve
from .hashing import sha256

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}


def serialize_point_uncompressed(point: AffinePoint) -> bytes:
    if point.is_infinity:
        raise ValueError("the point at infinity has no SEC1 encoding")
    assert point.x is not None and point.y is not None
    return b"\x04" + point.x.to_int().to_bytes(32, "big") + point.y.to_int().to_bytes(32, "big")


def serialize_point_compressed(point: AffinePoint) -> bytes:
    if point.is_infinity:
        raise ValueError("the point at infinity has no SEC1 encoding")
    assert point.x is not None and point.y is not None
    prefix = b"\x03" if point.y.to_int() & 1 else b"\x02"
    return prefix + point.x.to_int().to_bytes(32, "big")


def parse_point(curve: Curve, data: bytes) -> AffinePoint:
    if len(data) == 65 and data[0] == 0x04:
        x = curve.field.element(int.from_bytes(data[1:33], "big"))
        y = curve.field.element(int.from_bytes(data[33:65], "big"))
        point = AffinePoint(x, y)
    elif len(data) == 33 and data[0] in (0x02, 0x03):
        x = curve.field.element(int.from_bytes(data[1:33], "big"))
        right = x * x * x + curve.field.element(curve.a) * x + curve.field.element(curve.b)
        y = right.sqrt()
        if (y.to_int() & 1) != (data[0] & 1):
            y = -y
        point = AffinePoint(x, y)
    else:
        raise ValueError("unsupported SEC1 point encoding")
    if not curve.is_on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def encode_der_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative DER length")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_der_length(len(content)) + content


def _decode_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite DER length is not allowed")
    if count > 4 or offset + count > len(data):
        raise ValueError("invalid DER length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise ValueError("non-minimal DER length")
    return length, offset + count


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated DER element")
    tag = data[offset]
    length, content_offset = _decode_der_length(data, offset + 1)
    end = content_offset + length
    if end > len(data):
        raise ValueError("truncated DER content")
    return tag, data[content_offset:end], end


def encode_der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("DER integer must be non-negative")
    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    return _der(0x02, encoded)


def decode_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    tag, content, end = _read_tlv(data, offset)
    if tag != 0x02:
        raise ValueError("expected a DER INTEGER")
    if not content:
        raise ValueError("empty DER INTEGER")
    if content[0] & 0x80:
        raise ValueError("negative DER INTEGER")
    if len(content) > 1 and content[0] == 0x00 and content[1] < 0x80:
        raise ValueError("non-minimal DER INTEGER")
    return int.from_bytes(content, "big"), end


def encode_der_signature(r: int | BigInt, s: int | BigInt) -> bytes:
    r_value = r.to_int() if isinstance(r, BigInt) else r
    s_value = s.to_int() if isinstance(s, BigInt) else s
    return _der(0x30, encode_der_integer(r_value) + encode_der_integer(s_value))


def decode_der_signature(data: bytes) -> tuple[BigInt, BigInt]:
    tag, content, end = _read_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise ValueError("expected a single DER SEQUENCE")
    r, offset = decode_der_integer(content, 0)
    s, offset = decode_der_integer(content, offset)
    if offset != len(content):
        raise ValueError("trailing data in DER signature")
    if r == 0 or s == 0:
        raise ValueError("signature values must be positive")
    return BigInt.from_int(r), BigInt.from_int(s)


def _encode_oid(dotted: str) -> bytes:
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2:
        raise ValueError("OID needs at least two arcs")
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunks = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunks.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunks))
    return _der(0x06, bytes(body))


_CURVE_OIDS = {
    "secp256k1": "1.3.132.0.10",
    "P-256": "1.2.840.10045.3.1.7",
}
_EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"


def _pem(label: str, der: bytes) -> str:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def encode_ec_private_key_pem(curve: Curve, scalar: int | BigInt, public_key: AffinePoint) -> str:
    """SEC1 ECPrivateKey with the named curve and public key embedded."""
    value = scalar.to_int() if isinstance(scalar, BigInt) else scalar
    if curve.name not in _CURVE_OIDS:
        raise ValueError(f"no OID registered for {curve.name}")
    version = encode_der_integer(1)
    private_key = _der(0x04, value.to_bytes(32, "big"))
    parameters = _der(0xA0, _encode_oid(_CURVE_OIDS[curve.name]))
    public_bits = _der(0x03, b"\x00" + serialize_point_uncompressed(public_key))
    public_key_field = _der(0xA1, public_bits)
    der = _der(0x30, version + private_key + parameters + public_key_field)
    return _pem("EC PRIVATE KEY", der)


def encode_ec_public_key_pem(curve: Curve, public_key: AffinePoint) -> str:
    """SubjectPublicKeyInfo for a named short Weierstrass curve."""
    if curve.name not in _CURVE_OIDS:
        raise ValueError(f"no OID registered for {curve.name}")
    algorithm = _der(
        0x30,
        _encode_oid(_EC_PUBLIC_KEY_OID) + _encode_oid(_CURVE_OIDS[curve.name]),
    )
    subject_public_key = _der(0x03, b"\x00" + serialize_point_uncompressed(public_key))
    return _pem("PUBLIC KEY", _der(0x30, algorithm + subject_public_key))


def base58_encode(data: bytes) -> str:
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    return "1" * leading_zeros + encoded


def base58_decode(text: str) -> bytes:
    value = 0
    for character in text:
        if character not in _BASE58_INDEX:
            raise ValueError(f"invalid Base58 character: {character!r}")
        value = value * 58 + _BASE58_INDEX[character]
    leading_zeros = len(text) - len(text.lstrip("1"))
    body = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * leading_zeros + body


def base58check_encode(payload: bytes) -> str:
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)


def base58check_decode(text: str) -> bytes:
    decoded = base58_decode(text)
    if len(decoded) < 5:
        raise ValueError("Base58Check payload is too short")
    payload, checksum = decoded[:-4], decoded[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        raise ValueError("Base58Check checksum mismatch")
    return payload
