"""Demonstrate the Hamming-weight timing leak and the ladder countermeasure."""

from __future__ import annotations

import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from crypto_lab.curves import SECP256K1, OpCounter  # noqa: E402
from crypto_lab.scalarmult import double_and_add, montgomery_ladder  # noqa: E402

LOW_WEIGHT = 1 << 255
HIGH_WEIGHT = SECP256K1.n - 1


def measure(function: Callable[[], object], repeats: int = 5) -> float:
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def operation_counts() -> None:
    print("## Structural operation counts")
    print()
    print("| Scalar | Algorithm | Doublings | Additions | Mixed additions | Inversions |")
    print("|---|---|---:|---:|---:|---:|")
    for name, scalar in (("one bit set", LOW_WEIGHT), ("n-1", HIGH_WEIGHT)):
        counter = OpCounter()
        double_and_add(SECP256K1, scalar, SECP256K1.g, counter=counter)
        print(
            f"| {name} | double-and-add | {counter.doublings} | {counter.additions} | "
            f"{counter.mixed_additions} | {counter.inversions} |"
        )
        counter = OpCounter()
        montgomery_ladder(SECP256K1, scalar, SECP256K1.g, counter=counter)
        print(
            f"| {name} | Montgomery ladder | {counter.doublings} | {counter.additions} | "
            f"{counter.mixed_additions} | {counter.inversions} |"
        )
    print()


def timings() -> None:
    print("## Wall-clock timings")
    print()
    print("| Scalar | Double-and-add | Montgomery ladder |")
    print("|---|---:|---:|")
    for name, scalar in (("one bit set", LOW_WEIGHT), ("n-1", HIGH_WEIGHT)):
        dbl = measure(lambda scalar=scalar: double_and_add(SECP256K1, scalar, SECP256K1.g))
        ladder = measure(lambda scalar=scalar: montgomery_ladder(SECP256K1, scalar, SECP256K1.g))
        print(f"| {name} | {dbl:.4f} s | {ladder:.4f} s |")
    print()
    print("Wall-clock numbers on a general-purpose OS and CPython are noisy and are not a")
    print("security measurement. The structural counts above show the algorithmic difference.")


def main() -> None:
    print("# Timing leak demonstration")
    print()
    print(
        "Both scalars have 256 bits. One has a single set bit; the other has almost all bits set."
    )
    print()
    operation_counts()
    timings()


if __name__ == "__main__":
    main()
