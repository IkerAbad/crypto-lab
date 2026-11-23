from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from crypto_lab.bigint import BigInt
from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import Signature, private_key_from_int, sign, verify
from crypto_lab.encoding import encode_ec_private_key_pem, encode_ec_public_key_pem

OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="OpenSSL is not installed")


def _run(arguments: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    assert OPENSSL is not None
    return subprocess.run(
        [OPENSSL, *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_keypair(tmp_path: Path) -> tuple[Path, Path, Path]:
    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF, SECP256K1)
    public_key = private_key.public_key()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    message_path = tmp_path / "message.bin"
    private_path.write_text(
        encode_ec_private_key_pem(private_key.curve, private_key.scalar, public_key.point)
    )
    public_path.write_text(encode_ec_public_key_pem(private_key.curve, public_key.point))
    message_path.write_bytes(b"crypto-lab OpenSSL interoperability")
    return private_path, public_path, message_path


def test_our_signature_verifies_with_openssl(tmp_path: Path) -> None:
    private_path, public_path, message_path = _write_keypair(tmp_path)
    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF, SECP256K1)
    signature = sign(private_key, message_path.read_bytes())
    signature_path = tmp_path / "signature.der"
    signature_path.write_bytes(signature.to_der())
    result = _run(
        [
            "dgst",
            "-sha256",
            "-verify",
            str(public_path),
            "-signature",
            str(signature_path),
            str(message_path),
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert "Verified OK" in result.stdout
    assert private_path.exists()


def test_openssl_signature_verifies_here(tmp_path: Path) -> None:
    _private_path, _public_path, message_path = _write_keypair(tmp_path)
    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF, SECP256K1)
    public_key = private_key.public_key()
    signature_path = tmp_path / "openssl.der"
    result = _run(
        [
            "dgst",
            "-sha256",
            "-sign",
            str(tmp_path / "private.pem"),
            "-out",
            str(signature_path),
            str(message_path),
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    signature = Signature.from_der(signature_path.read_bytes())
    assert verify(public_key, message_path.read_bytes(), signature)


def test_high_s_signature_is_accepted_by_openssl(tmp_path: Path) -> None:
    _private_path, public_path, message_path = _write_keypair(tmp_path)
    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF, SECP256K1)
    signature = sign(private_key, message_path.read_bytes())
    order = BigInt.from_int(SECP256K1.n)
    malleable = Signature(signature.r, order - signature.s)
    signature_path = tmp_path / "malleable.der"
    signature_path.write_bytes(malleable.to_der())
    result = _run(
        [
            "dgst",
            "-sha256",
            "-verify",
            str(public_path),
            "-signature",
            str(signature_path),
            str(message_path),
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert "Verified OK" in result.stdout


def test_openssl_rejects_tampered_message(tmp_path: Path) -> None:
    _private_path, public_path, message_path = _write_keypair(tmp_path)
    private_key = private_key_from_int(0x1234567890ABCDEF1234567890ABCDEF, SECP256K1)
    signature_path = tmp_path / "signature.der"
    signature_path.write_bytes(sign(private_key, message_path.read_bytes()).to_der())
    tampered_path = tmp_path / "tampered.bin"
    tampered_path.write_bytes(message_path.read_bytes() + b"!")
    result = _run(
        [
            "dgst",
            "-sha256",
            "-verify",
            str(public_path),
            "-signature",
            str(signature_path),
            str(tampered_path),
        ],
        tmp_path,
    )
    assert result.returncode != 0
    assert "Verified OK" not in result.stdout
