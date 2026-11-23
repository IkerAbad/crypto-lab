from __future__ import annotations

import pytest

from crypto_lab.curves import SECP256K1, OpCounter
from crypto_lab.scalarmult import (
    double_and_add,
    double_and_add_affine,
    montgomery_ladder,
    sliding_window,
)


@pytest.mark.parametrize("scalar", [0, 1, 2, 3, 5, 17, 255, 256, 12345, 2**128 + 12345])
def test_scalar_multiplication_methods_agree(scalar: int) -> None:
    g = SECP256K1.g
    expected = double_and_add(SECP256K1, scalar, g)
    for method in (sliding_window, montgomery_ladder):
        result = method(SECP256K1, scalar, g)
        assert result.x == expected.x
        assert result.y == expected.y


@pytest.mark.parametrize("scalar", [0, 1, 2, 3, 17, 255])
def test_affine_baseline_matches_jacobian(scalar: int) -> None:
    expected = double_and_add(SECP256K1, scalar, SECP256K1.g)
    result = double_and_add_affine(SECP256K1, scalar, SECP256K1.g)
    assert result.x == expected.x
    assert result.y == expected.y


@pytest.mark.parametrize("window", [2, 3, 4, 5, 8])
def test_sliding_window_widths(window: int) -> None:
    scalar = 0xDEADBEEF1234567890ABCDEF
    expected = double_and_add(SECP256K1, scalar, SECP256K1.g)
    result = sliding_window(SECP256K1, scalar, SECP256K1.g, window=window)
    assert result.x == expected.x
    assert result.y == expected.y


def test_ladder_rejects_negative_scalars() -> None:
    with pytest.raises(ValueError):
        montgomery_ladder(SECP256K1, -1, SECP256K1.g)


def test_double_and_add_operation_count_depends_on_hamming_weight() -> None:
    low = OpCounter()
    high = OpCounter()
    double_and_add(SECP256K1, 1 << 31, SECP256K1.g, counter=low)
    double_and_add(SECP256K1, (1 << 32) - 1, SECP256K1.g, counter=high)
    assert low.mixed_additions < high.mixed_additions


def test_ladder_operation_count_is_independent_of_hamming_weight() -> None:
    low = OpCounter()
    high = OpCounter()
    montgomery_ladder(SECP256K1, 1, SECP256K1.g, counter=low)
    montgomery_ladder(SECP256K1, (1 << 32) - 1, SECP256K1.g, counter=high)
    assert low.doublings == high.doublings
    assert low.additions == high.additions
    assert low.mixed_additions == high.mixed_additions
    assert low.inversions == high.inversions


def test_zero_scalar_is_infinity() -> None:
    assert double_and_add(SECP256K1, 0, SECP256K1.g).is_infinity
    assert sliding_window(SECP256K1, 0, SECP256K1.g).is_infinity
    assert montgomery_ladder(SECP256K1, 0, SECP256K1.g).is_infinity
