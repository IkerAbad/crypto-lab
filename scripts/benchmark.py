"""Benchmark affine vs Jacobian arithmetic and scalar multiplication methods."""

from __future__ import annotations

import os
import platform
import statistics
import sys
import time
from collections.abc import Callable
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from crypto_lab.bigint import BigInt  # noqa: E402
from crypto_lab.bip32 import HARDENED_OFFSET, derive_child, master_key_from_seed  # noqa: E402
from crypto_lab.curves import SECP256K1  # noqa: E402
from crypto_lab.ecdsa import (  # noqa: E402
    find_recovery_id,
    private_key_from_int,
    recover_public_key,
    sign,
    verify,
)
from crypto_lab.hashing import hmac_sha256, sha256  # noqa: E402
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


def format_duration(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:.2f} us"
    if seconds < 1:
        return f"{seconds * 1e3:.2f} ms"
    return f"{seconds:.4f} s"


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


def per_operation_benchmark() -> None:
    curve = SECP256K1
    field = curve.field
    a = field.element(0x1234567890ABCDEF1234567890ABCDEF)
    b = field.element(0x0FEDCBA9876543210FEDCBA987654321)
    point_a = double_and_add(curve, 12345, curve.g)
    point_b = double_and_add(curve, 54321, curve.g)
    jacobian_a = curve.affine_to_jacobian(point_a)
    jacobian_b = curve.affine_to_jacobian(point_b)

    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF)
    message = b"per-operation benchmark"
    signature = sign(private_key, message)
    recovery_id = find_recovery_id(private_key.public_key(), message, signature)
    assert recovery_id is not None

    def sliding_256() -> object:
        return sliding_window(curve, 0xDEADBEEF12345678, curve.g)

    def ladder_256() -> object:
        return montgomery_ladder(curve, 0xDEADBEEF12345678, curve.g)

    def recovery() -> object:
        return recover_public_key(curve, message, signature, recovery_id)

    benchmark = master_key_from_seed(b"benchmark seed")
    operations: list[tuple[str, Callable[[], object], int]] = [
        ("Field addition", lambda: a + b, 20000),
        ("Field subtraction", lambda: a - b, 20000),
        ("Field multiplication", lambda: a * b, 20000),
        ("Field inversion", lambda: a.inverse(), 200),
        ("Field square root", lambda: (a * a).sqrt(), 200),
        ("Point doubling (affine)", lambda: curve.double_affine(point_a), 200),
        ("Point doubling (Jacobi)", lambda: curve.double_jacobian(jacobian_a), 2000),
        ("Point addition (affine)", lambda: curve.add_affine(point_a, point_b), 200),
        ("Point addition (Jacobi)", lambda: curve.add_jacobian(jacobian_a, jacobian_b), 2000),
        ("Mixed addition (Jacobi + affine)", lambda: curve.add_mixed(jacobian_a, point_b), 2000),
        ("Scalar multiplication (sliding w=4)", sliding_256, 2),
        ("Scalar multiplication (ladder)", ladder_256, 2),
        ("ECDSA sign", lambda: sign(private_key, message), 3),
        ("ECDSA verify", lambda: verify(private_key.public_key(), message, signature), 3),
        ("ECDSA recover public key", recovery, 2),
        ("SHA-256 (1 KiB)", lambda: sha256(b"a" * 1024), 2000),
        ("HMAC-SHA256 (1 KiB)", lambda: hmac_sha256(b"key", b"a" * 1024), 1000),
        ("BIP32 master from seed", lambda: master_key_from_seed(b"benchmark seed"), 200),
        ("BIP32 first hardened child", lambda: derive_child(benchmark, HARDENED_OFFSET), 2),
    ]

    print("## Per-operation timings")
    print()
    print("| Operation | Median time |")
    print("|---|---:|")
    for name, function, repeats in operations:
        duration = measure(function, repeats)
        print(f"| {name} | {format_duration(duration)} |")
    print()


def main() -> None:
    print("# Benchmark")
    print()
    print(f"- Date: {date.today().isoformat()}")
    print(f"- Python: {platform.python_version()}")
    print(f"- Platform: {platform.platform()}")
    print(f"- Processor: {platform.processor()}")
    print(f"- Logical CPUs: {os.cpu_count()}")
    print()
    modular_multiplication_benchmark()
    scalar_multiplication_benchmark()
    per_operation_benchmark()
    print(
        "Times are medians. The affine baseline performs one field inversion per point operation."
    )
    print("The ladder uses branch-free doubling and ladder addition, which costs extra field work.")


if __name__ == "__main__":
    main()
