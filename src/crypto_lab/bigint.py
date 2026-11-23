"""Arbitrary-precision unsigned integers built from 64-bit limbs.

The representation is a little-endian tuple of 64-bit limbs. Python's ``int``
is only used as a 64-bit (or 128-bit accumulator) word; the algorithms for
addition, subtraction, schoolbook multiplication, Knuth division, extended
Euclid and modular exponentiation are implemented here.
"""

from __future__ import annotations

import builtins
from typing import Final

LIMB_BITS: Final = 64
BASE: Final = 1 << LIMB_BITS
MASK: Final = BASE - 1


def _normalize(limbs: tuple[int, ...]) -> tuple[int, ...]:
    end = len(limbs)
    while end > 0 and limbs[end - 1] == 0:
        end -= 1
    return limbs[:end]


class BigInt:
    """Immutable unsigned integer stored as base-2^64 limbs."""

    __slots__ = ("limbs",)

    ZERO: BigInt
    ONE: BigInt

    def __init__(self, limbs: tuple[int, ...] = ()) -> None:
        self.limbs = _normalize(limbs)

    @classmethod
    def from_int(cls, value: int) -> BigInt:
        if value < 0:
            raise ValueError("BigInt is unsigned")
        limbs: list[int] = []
        while value:
            limbs.append(value & MASK)
            value >>= LIMB_BITS
        return cls(tuple(limbs))

    @classmethod
    def from_bytes(cls, data: bytes) -> BigInt:
        if not data:
            return cls()
        padding = (-len(data)) % 8
        padded = b"\x00" * padding + data
        limbs = tuple(
            int.from_bytes(padded[i : i + 8], "big") for i in range(len(padded) - 8, -8, -8)
        )
        return cls(limbs)

    @classmethod
    def from_hex(cls, value: str) -> BigInt:
        text = value.removeprefix("0x").removeprefix("0X")
        if not text:
            return cls()
        if len(text) % 2:
            text = "0" + text
        return cls.from_bytes(bytes.fromhex(text))

    def to_int(self) -> int:
        value = 0
        for limb in reversed(self.limbs):
            value = (value << LIMB_BITS) | limb
        return value

    def to_bytes(self, length: int | None = None) -> bytes:
        needed = (self.bit_length() + 7) // 8
        if length is None:
            length = needed
        if length < needed:
            raise OverflowError("integer does not fit in the requested length")
        if length == 0:
            return b""
        out = bytearray(length)
        for i in range(length):
            limb = self.limbs[i // 8] if i // 8 < len(self.limbs) else 0
            out[length - 1 - i] = (limb >> ((i % 8) * 8)) & 0xFF
        return bytes(out)

    def to_hex(self) -> str:
        if not self.limbs:
            return "0"
        return self.to_bytes().hex()

    def bit_length(self) -> int:
        if not self.limbs:
            return 0
        return (len(self.limbs) - 1) * LIMB_BITS + self.limbs[-1].bit_length()

    def bit(self, index: int) -> int:
        if index < 0:
            raise ValueError("bit index must be non-negative")
        if index // LIMB_BITS >= len(self.limbs):
            return 0
        return (self.limbs[index // LIMB_BITS] >> (index % LIMB_BITS)) & 1

    def is_odd(self) -> bool:
        return bool(self.limbs and self.limbs[0] & 1)

    def is_zero(self) -> bool:
        return not self.limbs

    def __bool__(self) -> bool:
        return bool(self.limbs)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BigInt):
            return NotImplemented
        return self.limbs == other.limbs

    def __hash__(self) -> int:
        return hash(self.limbs)

    def __lt__(self, other: BigInt) -> bool:
        if len(self.limbs) != len(other.limbs):
            return len(self.limbs) < len(other.limbs)
        for left, right in zip(reversed(self.limbs), reversed(other.limbs), strict=True):
            if left != right:
                return left < right
        return False

    def __le__(self, other: BigInt) -> bool:
        return self == other or self < other

    def __add__(self, other: BigInt) -> BigInt:
        if not isinstance(other, BigInt):
            return NotImplemented
        size = max(len(self.limbs), len(other.limbs))
        out: list[int] = []
        carry = 0
        for i in range(size):
            a = self.limbs[i] if i < len(self.limbs) else 0
            b = other.limbs[i] if i < len(other.limbs) else 0
            total = a + b + carry
            out.append(total & MASK)
            carry = total >> LIMB_BITS
        if carry:
            out.append(carry)
        return BigInt(tuple(out))

    def __sub__(self, other: BigInt) -> BigInt:
        if not isinstance(other, BigInt):
            return NotImplemented
        if self < other:
            raise ValueError("negative result")
        out: list[int] = []
        borrow = 0
        for i in range(len(self.limbs)):
            a = self.limbs[i]
            b = other.limbs[i] if i < len(other.limbs) else 0
            diff = a - b - borrow
            if diff < 0:
                diff += BASE
                borrow = 1
            else:
                borrow = 0
            out.append(diff)
        if borrow:
            raise AssertionError("unreachable borrow")
        return BigInt(tuple(out))

    def __mul__(self, other: BigInt) -> BigInt:
        if not isinstance(other, BigInt):
            return NotImplemented
        if not self.limbs or not other.limbs:
            return BigInt()
        out = [0] * (len(self.limbs) + len(other.limbs))
        for i, a in enumerate(self.limbs):
            carry = 0
            for j, b in enumerate(other.limbs):
                total = out[i + j] + a * b + carry
                out[i + j] = total & MASK
                carry = total >> LIMB_BITS
            k = i + len(other.limbs)
            while carry:
                total = out[k] + carry
                out[k] = total & MASK
                carry = total >> LIMB_BITS
                k += 1
        return BigInt(tuple(out))

    def __floordiv__(self, other: BigInt) -> BigInt:
        return divmod(self, other)[0]

    def __mod__(self, other: BigInt) -> BigInt:
        return divmod(self, other)[1]

    def __divmod__(self, other: BigInt) -> tuple[BigInt, BigInt]:
        return divmod(self, other)

    def __lshift__(self, bits: int) -> BigInt:
        if bits < 0:
            raise ValueError("negative shift")
        if not self.limbs:
            return BigInt()
        word_shift, bit_shift = builtins.divmod(bits, LIMB_BITS)
        out = [0] * word_shift
        if bit_shift == 0:
            out.extend(self.limbs)
        else:
            carry = 0
            for limb in self.limbs:
                total = (limb << bit_shift) | carry
                out.append(total & MASK)
                carry = total >> LIMB_BITS
            if carry:
                out.append(carry)
        return BigInt(tuple(out))

    def __rshift__(self, bits: int) -> BigInt:
        if bits < 0:
            raise ValueError("negative shift")
        if bits == 0 or not self.limbs:
            return self
        word_shift, bit_shift = builtins.divmod(bits, LIMB_BITS)
        if word_shift >= len(self.limbs):
            return BigInt()
        source = self.limbs[word_shift:]
        if bit_shift == 0:
            return BigInt(source)
        out: list[int] = []
        carry = 0
        for limb in reversed(source):
            out.append((limb >> bit_shift) | (carry << (LIMB_BITS - bit_shift)))
            carry = limb & ((1 << bit_shift) - 1)
        out.reverse()
        return BigInt(tuple(out))

    def __repr__(self) -> str:
        return f"BigInt(0x{self.to_hex()})"


def divmod(a: BigInt, b: BigInt) -> tuple[BigInt, BigInt]:  # noqa: A001
    """Knuth Algorithm D division with base-2^64 limbs."""
    if not b:
        raise ZeroDivisionError("division by zero")
    if a < b:
        return BigInt(), a
    if len(b.limbs) == 1:
        divisor = b.limbs[0]
        quotient = [0] * len(a.limbs)
        remainder = 0
        for i in range(len(a.limbs) - 1, -1, -1):
            current = (remainder << LIMB_BITS) | a.limbs[i]
            quotient[i] = current // divisor
            remainder = current % divisor
        return BigInt(tuple(quotient)), BigInt((remainder,))

    shift = LIMB_BITS - b.limbs[-1].bit_length()
    if shift == LIMB_BITS:
        shift = 0
    u = list((a << shift).limbs)
    v = (b << shift).limbs
    n = len(v)
    m = len(u) - n
    quotient = [0] * (m + 1)
    if len(u) == m + n:
        u.append(0)

    for j in range(m, -1, -1):
        numerator = (u[j + n] << LIMB_BITS) | u[j + n - 1]
        qhat = numerator // v[n - 1]
        rhat = numerator % v[n - 1]
        if qhat >= BASE:
            qhat = BASE - 1
            rhat = numerator - qhat * v[n - 1]
        while qhat * v[n - 2] > (rhat << LIMB_BITS) + u[j + n - 2]:
            qhat -= 1
            rhat += v[n - 1]
            if rhat >= BASE:
                break

        borrow = 0
        for i in range(n):
            product = qhat * v[i]
            diff = u[j + i] - borrow - (product & MASK)
            u[j + i] = diff & MASK
            borrow = (product >> LIMB_BITS) - (diff >> LIMB_BITS)
        diff = u[j + n] - borrow
        u[j + n] = diff & MASK
        if diff < 0:
            qhat -= 1
            carry = 0
            for i in range(n):
                total = u[j + i] + v[i] + carry
                u[j + i] = total & MASK
                carry = total >> LIMB_BITS
            u[j + n] = (u[j + n] + carry) & MASK
        quotient[j] = qhat

    remainder_limbs = u[:n]
    if shift:
        shifted = [0] * n
        carry = 0
        for i in range(n - 1, -1, -1):
            shifted[i] = (remainder_limbs[i] >> shift) | (carry << (LIMB_BITS - shift))
            carry = remainder_limbs[i] & ((1 << shift) - 1)
        remainder_limbs = shifted
    return BigInt(tuple(quotient)), BigInt(tuple(remainder_limbs))


def mod_inverse(a: BigInt, modulus: BigInt) -> BigInt:
    """Modular inverse via the extended Euclidean algorithm."""
    if modulus <= BigInt.ONE:
        raise ValueError("modulus must be greater than one")
    a = a % modulus
    if not a:
        raise ZeroDivisionError("zero has no modular inverse")
    r0, r1 = modulus, a
    s0, s1 = BigInt.ZERO, BigInt.ONE
    while r1:
        quotient, remainder = divmod(r0, r1)
        r0, r1 = r1, remainder
        product = (quotient * s1) % modulus
        s0, s1 = s1, (s0 - product if s0 >= product else s0 + modulus - product)
    if r0 != BigInt.ONE:
        raise ValueError("inverse does not exist")
    return s0


def pow_mod(base: BigInt, exponent: BigInt, modulus: BigInt) -> BigInt:
    """Square-and-multiply modular exponentiation."""
    if modulus <= BigInt.ZERO:
        raise ValueError("modulus must be positive")
    if not exponent:
        return BigInt.ONE % modulus
    result = BigInt.ONE % modulus
    factor = base % modulus
    while exponent:
        if exponent.is_odd():
            result = (result * factor) % modulus
        factor = (factor * factor) % modulus
        exponent = exponent >> 1
    return result


BigInt.ZERO = BigInt()
BigInt.ONE = BigInt((1,))
