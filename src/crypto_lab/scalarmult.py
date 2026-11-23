"""Scalar multiplication: double-and-add, sliding window and Montgomery ladder."""

from __future__ import annotations

from .bigint import BigInt
from .curves import AffinePoint, Curve, JacobianPoint, OpCounter


def _as_bigint(scalar: int | BigInt) -> BigInt:
    if isinstance(scalar, BigInt):
        return scalar
    if scalar < 0:
        raise ValueError("scalar must be non-negative")
    return BigInt.from_int(scalar)


def double_and_add_affine(
    curve: Curve,
    scalar: int | BigInt,
    point: AffinePoint,
    counter: OpCounter | None = None,
) -> AffinePoint:
    """Affine double-and-add, kept as the baseline for the Jacobi benchmark."""
    k = _as_bigint(scalar)
    if not k or point.is_infinity:
        return curve.infinity()
    result = curve.infinity()
    for index in range(k.bit_length() - 1, -1, -1):
        result = curve.double_affine(result, counter)
        if k.bit(index):
            result = curve.add_affine(result, point, counter)
    return result


def double_and_add(
    curve: Curve,
    scalar: int | BigInt,
    point: AffinePoint,
    counter: OpCounter | None = None,
) -> AffinePoint:
    """Left-to-right double-and-add. Variable time by design."""
    k = _as_bigint(scalar)
    if not k or point.is_infinity:
        return curve.infinity()
    result = JacobianPoint(curve.field.zero, curve.field.zero, curve.field.zero)
    for index in range(k.bit_length() - 1, -1, -1):
        result = curve.double_jacobian(result, counter)
        if k.bit(index):
            result = curve.add_mixed(result, point, counter)
    return curve.jacobian_to_affine(result, counter)


def sliding_window(
    curve: Curve,
    scalar: int | BigInt,
    point: AffinePoint,
    window: int = 4,
    counter: OpCounter | None = None,
) -> AffinePoint:
    """Right-to-left sliding-window multiplication with a precomputed odd table."""
    if window < 2 or window > 8:
        raise ValueError("window width must be between 2 and 8")
    k = _as_bigint(scalar)
    if not k or point.is_infinity:
        return curve.infinity()

    base = curve.affine_to_jacobian(point)
    twice = curve.double_jacobian(base, counter)
    table_size = 1 << (window - 1)
    table_jacobian = [base]
    for _ in range(1, table_size):
        table_jacobian.append(curve.add_jacobian(table_jacobian[-1], twice, counter))
    table = curve.batch_to_affine(table_jacobian, counter)

    result = JacobianPoint(curve.field.zero, curve.field.zero, curve.field.zero)
    index = k.bit_length() - 1
    while index >= 0:
        if k.bit(index) == 0:
            result = curve.double_jacobian(result, counter)
            index -= 1
            continue
        start = max(index - window + 1, 0)
        while k.bit(start) == 0:
            start += 1
        value = 0
        for bit_index in range(index, start - 1, -1):
            value = (value << 1) | k.bit(bit_index)
        for _ in range(index - start + 1):
            result = curve.double_jacobian(result, counter)
        result = curve.add_mixed(result, table[(value - 1) // 2], counter)
        index = start - 1
    return curve.jacobian_to_affine(result, counter)


def _cswap(
    curve: Curve, bit: int, left: JacobianPoint, right: JacobianPoint
) -> tuple[JacobianPoint, JacobianPoint]:
    field = curve.field
    return (
        JacobianPoint(
            field.select(bit, left.x, right.x),
            field.select(bit, left.y, right.y),
            field.select(bit, left.z, right.z),
        ),
        JacobianPoint(
            field.select(bit, right.x, left.x),
            field.select(bit, right.y, left.y),
            field.select(bit, right.z, left.z),
        ),
    )


def montgomery_ladder(
    curve: Curve,
    scalar: int | BigInt,
    point: AffinePoint,
    counter: OpCounter | None = None,
) -> AffinePoint:
    """Fixed-iteration Montgomery ladder with arithmetic conditional swaps.

    The working scalar is shifted by one or two copies of the curve order so it
    always has exactly 257 bits. Since nP is the point at infinity, the shift
    does not change the result, but it removes bit-length and leading-zero
    leakage from the loop. Python itself does not provide hard constant-time
    guarantees; see the README.
    """
    order = BigInt.from_int(curve.n)
    k = _as_bigint(scalar) % order
    if point.is_infinity or not k:
        return curve.infinity()

    field = curve.field
    lower = JacobianPoint(field.zero, field.zero, field.zero)
    upper = curve.affine_to_jacobian(point)
    for bit_index in range(order.bit_length() - 1, -1, -1):
        bit = k.bit(bit_index)
        lower, upper = _cswap(curve, bit, lower, upper)
        upper = curve.add_jacobian_ladder(lower, upper, counter)
        lower = curve.double_jacobian(lower, counter)
        lower, upper = _cswap(curve, bit, lower, upper)
    return curve.jacobian_to_affine(lower, counter)


def scalar_multiply(
    curve: Curve,
    scalar: int | BigInt,
    point: AffinePoint,
    method: str = "ladder",
) -> AffinePoint:
    """Convenience dispatcher used by higher-level primitives."""
    if method == "ladder":
        return montgomery_ladder(curve, scalar, point)
    if method == "double-and-add":
        return double_and_add(curve, scalar, point)
    if method == "sliding-window":
        return sliding_window(curve, scalar, point)
    raise ValueError(f"unknown scalar multiplication method: {method}")
