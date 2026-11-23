"""Short Weierstrass curves over prime fields, with affine and Jacobian points."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .field import FieldElement, MontgomeryField


@dataclass
class OpCounter:
    """Counts group operations for structural timing analysis."""

    doublings: int = 0
    additions: int = 0
    mixed_additions: int = 0
    inversions: int = 0


@dataclass(frozen=True, slots=True)
class AffinePoint:
    x: FieldElement | None
    y: FieldElement | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __post_init__(self) -> None:
        if (self.x is None) != (self.y is None):
            raise ValueError("affine coordinates must both be present or both absent")


INFINITY: Final = AffinePoint(None, None)


@dataclass(frozen=True, slots=True)
class JacobianPoint:
    x: FieldElement
    y: FieldElement
    z: FieldElement

    @property
    def is_infinity(self) -> bool:
        return self.z.is_zero()


def _select_jacobian(
    curve: Curve, bit: int, left: JacobianPoint, right: JacobianPoint
) -> JacobianPoint:
    field = curve.field
    return JacobianPoint(
        field.select(bit, left.x, right.x),
        field.select(bit, left.y, right.y),
        field.select(bit, left.z, right.z),
    )


class Curve:
    """A short Weierstrass curve y^2 = x^3 + ax + b over F_p."""

    __slots__ = (
        "name",
        "p",
        "a",
        "b",
        "n",
        "gx",
        "gy",
        "field",
        "g",
        "a_fe",
        "b_fe",
        "_two",
        "_three",
        "_four",
        "_eight",
    )

    def __init__(
        self,
        name: str,
        p: int,
        a: int,
        b: int,
        n: int,
        gx: int,
        gy: int,
    ) -> None:
        self.name = name
        self.p = p
        self.a = a % p
        self.b = b % p
        self.n = n
        self.gx = gx
        self.gy = gy
        self.field = MontgomeryField(p)
        self.a_fe = self.field.element(self.a)
        self.b_fe = self.field.element(self.b)
        self._two = self.field.element(2)
        self._three = self.field.element(3)
        self._four = self.field.element(4)
        self._eight = self.field.element(8)
        self.g = AffinePoint(self.field.element(gx), self.field.element(gy))
        if not self.is_on_curve(self.g):
            raise ValueError(f"generator is not on {name}")

    def infinity(self) -> AffinePoint:
        return INFINITY

    def is_on_curve(self, point: AffinePoint) -> bool:
        if point.is_infinity:
            return True
        assert point.x is not None and point.y is not None
        x, y = point.x, point.y
        return y * y == x * x * x + self.a_fe * x + self.b_fe

    def affine_to_jacobian(self, point: AffinePoint) -> JacobianPoint:
        if point.is_infinity:
            return JacobianPoint(self.field.zero, self.field.zero, self.field.zero)
        assert point.x is not None and point.y is not None
        return JacobianPoint(point.x, point.y, self.field.one)

    def jacobian_to_affine(
        self, point: JacobianPoint, counter: OpCounter | None = None
    ) -> AffinePoint:
        if point.is_infinity:
            return INFINITY
        if counter is not None:
            counter.inversions += 1
        z_inverse = point.z.inverse()
        z_inverse_squared = z_inverse * z_inverse
        x = point.x * z_inverse_squared
        y = point.y * z_inverse_squared * z_inverse
        return AffinePoint(x, y)

    def batch_to_affine(
        self, points: list[JacobianPoint], counter: OpCounter | None = None
    ) -> list[AffinePoint]:
        finite = [point for point in points if not point.is_infinity]
        if not finite:
            return [INFINITY for _ in points]
        if counter is not None:
            counter.inversions += 1
        inverses = self.field.batch_inverse([point.z for point in finite])
        result: list[AffinePoint] = []
        index = 0
        for point in points:
            if point.is_infinity:
                result.append(INFINITY)
                continue
            z_inverse = inverses[index]
            index += 1
            z_inverse_squared = z_inverse * z_inverse
            result.append(
                AffinePoint(point.x * z_inverse_squared, point.y * z_inverse_squared * z_inverse)
            )
        return result

    def negate(self, point: AffinePoint) -> AffinePoint:
        if point.is_infinity:
            return point
        assert point.y is not None
        return AffinePoint(point.x, -point.y)

    def double_affine(self, point: AffinePoint, counter: OpCounter | None = None) -> AffinePoint:
        if point.is_infinity:
            return point
        assert point.x is not None and point.y is not None
        if counter is not None:
            counter.doublings += 1
        if point.y == self.field.zero:
            return INFINITY
        if counter is not None:
            counter.inversions += 1
        slope = (self._three * point.x * point.x + self.a_fe) * (self._two * point.y).inverse()
        x3 = slope * slope - self._two * point.x
        y3 = slope * (point.x - x3) - point.y
        return AffinePoint(x3, y3)

    def add_affine(
        self, left: AffinePoint, right: AffinePoint, counter: OpCounter | None = None
    ) -> AffinePoint:
        if left.is_infinity:
            return right
        if right.is_infinity:
            return left
        if counter is not None:
            counter.additions += 1
        assert left.x is not None and left.y is not None
        assert right.x is not None and right.y is not None
        if left.x == right.x:
            if left.y + right.y == self.field.zero:
                return INFINITY
            return self.double_affine(left, counter)
        if counter is not None:
            counter.inversions += 1
        slope = (right.y - left.y) * (right.x - left.x).inverse()
        x3 = slope * slope - left.x - right.x
        y3 = slope * (left.x - x3) - left.y
        return AffinePoint(x3, y3)

    def double_jacobian(
        self, point: JacobianPoint, counter: OpCounter | None = None
    ) -> JacobianPoint:
        if counter is not None:
            counter.doublings += 1
        if self.a == 0:
            a = point.x * point.x
            b = point.y * point.y
            c = b * b
            d = self._two * ((point.x + b) * (point.x + b) - a - c)
            e = self._three * a
            f = e * e
            x3 = f - self._two * d
            y3 = e * (d - x3) - self._eight * c
            z3 = self._two * point.y * point.z
            return _select_jacobian(
                self,
                int(point.z.is_zero()) | int(point.y.is_zero()),
                JacobianPoint(x3, y3, z3),
                JacobianPoint(self.field.zero, self.field.zero, self.field.zero),
            )

        xx = point.x * point.x
        yy = point.y * point.y
        yyyy = yy * yy
        zz = point.z * point.z
        s = self._two * ((point.x + yy) * (point.x + yy) - xx - yyyy)
        m = self._three * xx + self.a_fe * zz * zz
        t = m * m - self._two * s
        x3 = t
        y3 = m * (s - t) - self._eight * yyyy
        z3 = (point.y + point.z) * (point.y + point.z) - yy - zz
        return _select_jacobian(
            self,
            int(point.z.is_zero()) | int(point.y.is_zero()),
            JacobianPoint(x3, y3, z3),
            JacobianPoint(self.field.zero, self.field.zero, self.field.zero),
        )

    def add_jacobian(
        self, left: JacobianPoint, right: JacobianPoint, counter: OpCounter | None = None
    ) -> JacobianPoint:
        if left.is_infinity:
            return right
        if right.is_infinity:
            return left
        if counter is not None:
            counter.additions += 1
        z1z1 = left.z * left.z
        z2z2 = right.z * right.z
        u1 = left.x * z2z2
        u2 = right.x * z1z1
        s1 = left.y * right.z * z2z2
        s2 = right.y * left.z * z1z1
        h = u2 - u1
        r = self._two * (s2 - s1)
        if h == self.field.zero:
            if r == self.field.zero:
                return self.double_jacobian(left, counter)
            return JacobianPoint(self.field.zero, self.field.zero, self.field.zero)
        i = (self._two * h) * (self._two * h)
        j = h * i
        v = u1 * i
        x3 = r * r - j - self._two * v
        y3 = r * (v - x3) - self._two * s1 * j
        z3 = ((left.z + right.z) * (left.z + right.z) - z1z1 - z2z2) * h
        return JacobianPoint(x3, y3, z3)

    def add_jacobian_ladder(
        self, left: JacobianPoint, right: JacobianPoint, counter: OpCounter | None = None
    ) -> JacobianPoint:
        """Branch-free addition for finite or infinite ladder states.

        The Montgomery ladder never adds two equal finite points, so only the
        point-at-infinity cases need to be selected branch-free.
        """
        if counter is not None:
            counter.additions += 1
        z1z1 = left.z * left.z
        z2z2 = right.z * right.z
        u1 = left.x * z2z2
        u2 = right.x * z1z1
        s1 = left.y * right.z * z2z2
        s2 = right.y * left.z * z1z1
        h = u2 - u1
        r = self._two * (s2 - s1)
        i = (self._two * h) * (self._two * h)
        j = h * i
        v = u1 * i
        x3 = r * r - j - self._two * v
        y3 = r * (v - x3) - self._two * s1 * j
        z3 = ((left.z + right.z) * (left.z + right.z) - z1z1 - z2z2) * h
        result = JacobianPoint(x3, y3, z3)
        result = _select_jacobian(self, int(left.z.is_zero()), result, right)
        return _select_jacobian(self, int(right.z.is_zero()), result, left)

    def add_mixed(
        self, left: JacobianPoint, right: AffinePoint, counter: OpCounter | None = None
    ) -> JacobianPoint:
        if right.is_infinity:
            return left
        if left.is_infinity:
            return self.affine_to_jacobian(right)
        if counter is not None:
            counter.mixed_additions += 1
        assert right.x is not None and right.y is not None
        z1z1 = left.z * left.z
        u2 = right.x * z1z1
        s2 = right.y * left.z * z1z1
        h = u2 - left.x
        hh = h * h
        i = self._four * hh
        j = h * i
        r = self._two * (s2 - left.y)
        v = left.x * i
        if h == self.field.zero:
            if r == self.field.zero:
                return self.double_jacobian(left, counter)
            return JacobianPoint(self.field.zero, self.field.zero, self.field.zero)
        x3 = r * r - j - self._two * v
        y3 = r * (v - x3) - self._two * left.y * j
        z3 = (left.z + h) * (left.z + h) - z1z1 - hh
        return JacobianPoint(x3, y3, z3)


SECP256K1: Final = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

P256: Final = Curve(
    name="P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
