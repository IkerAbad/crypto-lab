"""Benchmark affine vs Jacobian arithmetic and scalar multiplication methods."""

from __future__ import annotations

import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from crypto_lab.bigint import BigInt  # noqa: E402
from crypto_lab.curves import SECP256K1  # noqa: E402
from crypto_lab.scalarmult import (  # noqa: E402
    double_and_add,
    double_and_add_affine,
    montgomery_ladder,
    sliding_window,
)


def measure(function: Callable[[], object], repeats: int) -> float:
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def modular_multiplication_benchmark() -> None:
    modulus = SECP256K1.p
    a = BigInt.from_int(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
    b = BigInt.from_int(0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321)
    field = SECP256K1.field
    fa = field.element(a.to_int() % modulus)
    fb = field.element(b.to_int() % modulus)
    bigint_time = measure(lambda: (a * b) % BigInt.from_int(modulus), 2000)
    field_time = measure(lambda: fa * fb, 2000)
    print("## 256-bit modular multiplication")
    print()
    print("| Implementation | Median time |")
    print("|---|---:|")
    print(f"| BigInt schoolbook + Knuth division | {bigint_time * 1e6:.2f} us |")
    print(f"| Montgomery field multiplication | {field_time * 1e6:.2f} us |")
    print()


def scalar_multiplication_benchmark() -> None:
    scalars = {
        32: 0xDEADBEEF,
        64: 0xDEADBEEF12345678,
        128: 0xDEADBEEF1234567890ABCDEF12345678,
        256: 0xDEADBEEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678,
    }
    print("## Scalar multiplication on secp256k1")
    print()
    print(
        "| Scalar bits | Affine double-and-add | Jacobi double-and-add | "
        "Sliding window (w=4) | Montgomery ladder |"
    )
    print("|---:|---:|---:|---:|---:|")
    for bits, scalar in scalars.items():
        repeats = 5 if bits <= 64 else 2 if bits <= 128 else 1
        affine_time = measure(
            lambda scalar=scalar: double_and_add_affine(SECP256K1, scalar, SECP256K1.g),
            repeats,
        )
        jacobi_time = measure(
            lambda scalar=scalar: double_and_add(SECP256K1, scalar, SECP256K1.g), repeats
        )
        window_time = measure(
            lambda scalar=scalar: sliding_window(SECP256K1, scalar, SECP256K1.g), repeats
        )
        ladder_time = measure(
            lambda scalar=scalar: montgomery_ladder(SECP256K1, scalar, SECP256K1.g), repeats
        )
        print(
            f"| {bits} | {affine_time:.4f} s | {jacobi_time:.4f} s | "
            f"{window_time:.4f} s | {ladder_time:.4f} s |"
        )
    print()


def main() -> None:
    print("# Benchmark")
    print()
    print(f"- Python: {platform.python_version()}")
    print(f"- Platform: {platform.platform()}")
    print(f"- Processor: {platform.processor()}")
    print()
    modular_multiplication_benchmark()
    scalar_multiplication_benchmark()
    print(
        "Times are medians. The affine baseline performs one field inversion per point operation."
    )
    print("The ladder uses branch-free doubling and ladder addition, which costs extra field work.")


if __name__ == "__main__":
    main()
