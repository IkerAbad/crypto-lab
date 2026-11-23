"""Prime-field arithmetic with Montgomery multiplication.

Field elements are four 64-bit limbs in Montgomery form. The CIOS
multiplication routine is written here rather than delegated to Python's
arbitrary-precision multiplication.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

LIMBS: Final = 4
LIMB_BITS: Final = 64
BASE: Final = 1 << LIMB_BITS
MASK: Final = BASE - 1


def _to_limbs(value: int) -> tuple[int, ...]:
    return tuple((value >> (LIMB_BITS * i)) & MASK for i in range(LIMBS))


def _from_limbs(limbs: tuple[int, ...]) -> int:
    value = 0
    for limb in reversed(limbs):
        value = (value << LIMB_BITS) | limb
    return value


class FieldElement:
    """An element of a 256-bit prime field, stored in Montgomery form."""

    __slots__ = ("field", "limbs")

    def __init__(self, field: MontgomeryField, limbs: tuple[int, ...]) -> None:
        self.field = field
        self.limbs = limbs

    def to_int(self) -> int:
        return self.field.to_int(self)

    def inverse(self) -> FieldElement:
        return self.field.inverse(self)

    def square(self) -> FieldElement:
        return self.field.square(self)

    def sqrt(self) -> FieldElement:
        return self.field.sqrt(self)

    def is_zero(self) -> bool:
        accumulator = 0
        for limb in self.limbs:
            accumulator |= limb
        return accumulator == 0

    def __add__(self, other: FieldElement) -> FieldElement:
        return self.field.add(self, other)

    def __sub__(self, other: FieldElement) -> FieldElement:
        return self.field.sub(self, other)

    def __neg__(self) -> FieldElement:
        return self.field.negate(self)

    def __mul__(self, other: FieldElement) -> FieldElement:
        return self.field.mul(self, other)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FieldElement):
            return NotImplemented
        return self.field is other.field and self.limbs == other.limbs

    def __hash__(self) -> int:
        return hash((self.field.modulus, self.limbs))

    def __repr__(self) -> str:
        return f"FieldElement(0x{self.to_int():064x})"


class MontgomeryField:
    """Prime field modulo an odd 256-bit modulus."""

    __slots__ = ("modulus", "n0", "r2", "p_limbs", "_one", "_zero")

    def __init__(self, modulus: int) -> None:
        if modulus <= 1 or modulus % 2 == 0:
            raise ValueError("modulus must be an odd integer greater than one")
        if modulus.bit_length() > 256:
            raise ValueError("this field implementation is limited to 256 bits")
        self.modulus = modulus
        self.p_limbs = _to_limbs(modulus)
        self.n0 = self._montgomery_n0(modulus)
        r = 1 << 256
        self.r2 = _to_limbs((r * r) % modulus)
        self._zero = FieldElement(self, (0, 0, 0, 0))
        self._one = self.from_limbs(_to_limbs(r % modulus))

    @staticmethod
    def _montgomery_n0(modulus: int) -> int:
        inverse = 1
        for _ in range(6):
            inverse = (inverse * (2 - modulus * inverse)) & MASK
        return (-inverse) & MASK

    @property
    def zero(self) -> FieldElement:
        return self._zero

    @property
    def one(self) -> FieldElement:
        return self._one

    def from_limbs(self, limbs: tuple[int, ...]) -> FieldElement:
        if len(limbs) != LIMBS or any(limb < 0 or limb > MASK for limb in limbs):
            raise ValueError("invalid limb representation")
        return FieldElement(self, limbs)

    def element(self, value: int) -> FieldElement:
        if value < 0 or value >= self.modulus:
            raise ValueError("value is outside the field")
        return self.from_limbs(self._mont_mul(_to_limbs(value), self.r2))

    def to_int(self, element: FieldElement) -> int:
        if element.field is not self:
            raise ValueError("element belongs to a different field")
        return _from_limbs(self._mont_mul(element.limbs, (1, 0, 0, 0)))

    def _mont_mul(self, a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
        p = self.p_limbs
        n0 = self.n0
        t = [0] * (LIMBS + 2)
        for i in range(LIMBS):
            carry = 0
            bi = b[i]
            for j in range(LIMBS):
                total = t[j] + a[j] * bi + carry
                t[j] = total & MASK
                carry = total >> LIMB_BITS
            total = t[LIMBS] + carry
            t[LIMBS] = total & MASK
            t[LIMBS + 1] = total >> LIMB_BITS

            m = (t[0] * n0) & MASK
            total = t[0] + m * p[0]
            carry = total >> LIMB_BITS
            for j in range(1, LIMBS):
                total = t[j] + m * p[j] + carry
                t[j - 1] = total & MASK
                carry = total >> LIMB_BITS
            total = t[LIMBS] + carry
            t[LIMBS - 1] = total & MASK
            t[LIMBS] = t[LIMBS + 1] + (total >> LIMB_BITS)

        result = t[:LIMBS]
        if t[LIMBS] or _from_limbs(tuple(result)) >= self.modulus:
            borrow = 0
            for i in range(LIMBS):
                diff = result[i] - p[i] - borrow
                result[i] = diff & MASK
                borrow = 1 if diff < 0 else 0
        return tuple(result)

    def add(self, a: FieldElement, b: FieldElement) -> FieldElement:
        self._check(a)
        self._check(b)
        out: list[int] = []
        carry = 0
        for i in range(LIMBS):
            total = a.limbs[i] + b.limbs[i] + carry
            out.append(total & MASK)
            carry = total >> LIMB_BITS
        if carry:
            borrow = 0
            for i in range(LIMBS):
                diff = out[i] - self.p_limbs[i] - borrow
                out[i] = diff & MASK
                borrow = 1 if diff < 0 else 0
            if carry - borrow:
                raise AssertionError("modular addition overflow")
        elif _from_limbs(tuple(out)) >= self.modulus:
            out = list(self._sub_limbs(tuple(out), self.p_limbs))
        return self.from_limbs(tuple(out))

    def sub(self, a: FieldElement, b: FieldElement) -> FieldElement:
        self._check(a)
        self._check(b)
        if _from_limbs(a.limbs) >= _from_limbs(b.limbs):
            return self.from_limbs(self._sub_limbs(a.limbs, b.limbs))
        return self.from_limbs(self._sub_limbs(self.p_limbs, self._sub_limbs(b.limbs, a.limbs)))

    def negate(self, a: FieldElement) -> FieldElement:
        self._check(a)
        if not any(a.limbs):
            return self._zero
        return self.from_limbs(self._sub_limbs(self.p_limbs, a.limbs))

    def mul(self, a: FieldElement, b: FieldElement) -> FieldElement:
        self._check(a)
        self._check(b)
        return self.from_limbs(self._mont_mul(a.limbs, b.limbs))

    def square(self, a: FieldElement) -> FieldElement:
        self._check(a)
        return self.from_limbs(self._mont_mul(a.limbs, a.limbs))

    def pow(self, base: FieldElement, exponent: int) -> FieldElement:
        self._check(base)
        if exponent < 0:
            raise ValueError("negative exponent")
        result = self._one
        factor = base
        while exponent:
            if exponent & 1:
                result = self.mul(result, factor)
            factor = self.mul(factor, factor)
            exponent >>= 1
        return result

    def inverse(self, a: FieldElement) -> FieldElement:
        self._check(a)
        if not any(a.limbs):
            raise ZeroDivisionError("zero has no inverse")
        return self.pow(a, self.modulus - 2)

    def sqrt(self, a: FieldElement) -> FieldElement:
        self._check(a)
        if self.modulus % 4 != 3:
            raise ValueError("square root requires a prime congruent to 3 mod 4")
        root = self.pow(a, (self.modulus + 1) // 4)
        if self.mul(root, root) != a:
            raise ValueError("value is not a quadratic residue")
        return root

    def batch_inverse(self, values: Sequence[FieldElement]) -> list[FieldElement]:
        if not values:
            return []
        for value in values:
            self._check(value)
            if not any(value.limbs):
                raise ZeroDivisionError("zero has no inverse")
        prefix = [self._one]
        for value in values:
            prefix.append(self.mul(prefix[-1], value))
        inverse_product = self.inverse(prefix[-1])
        result = [self._zero] * len(values)
        for i in range(len(values) - 1, -1, -1):
            result[i] = self.mul(inverse_product, prefix[i])
            inverse_product = self.mul(inverse_product, values[i])
        return result

    def select(self, bit: int, a: FieldElement, b: FieldElement) -> FieldElement:
        """Branch-free selection: bit 0 returns a, bit 1 returns b."""
        if bit not in (0, 1):
            raise ValueError("selection bit must be zero or one")
        self._check(a)
        self._check(b)
        mask = -bit
        return self.from_limbs(
            tuple(x ^ ((x ^ y) & mask) for x, y in zip(a.limbs, b.limbs, strict=True))
        )

    def _check(self, value: FieldElement) -> None:
        if value.field is not self:
            raise ValueError("element belongs to a different field")

    @staticmethod
    def _sub_limbs(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
        out: list[int] = []
        borrow = 0
        for x, y in zip(a, b, strict=True):
            diff = x - y - borrow
            if diff < 0:
                diff += BASE
                borrow = 1
            else:
                borrow = 0
            out.append(diff)
        if borrow:
            raise AssertionError("unreachable borrow")
        return tuple(out)
