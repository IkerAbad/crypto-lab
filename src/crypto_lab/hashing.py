"""SHA-256, SHA-512, RIPEMD-160 and HMAC, implemented without dependencies."""

from __future__ import annotations

from collections.abc import Callable

HashFunction = Callable[[bytes], bytes]

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF

_SHA256_K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

_SHA512_K = (
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
)


def _rotr32(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & _MASK32


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & _MASK32


def _rotr64(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (64 - shift))) & _MASK64


def sha256(data: bytes) -> bytes:
    """SHA-256 (FIPS 180-4)."""
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\x00" * ((-len(padded) - 8) % 64)
    padded += bit_length.to_bytes(8, "big")

    h = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)

        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + s1 + ch + _SHA256_K[i] + w[i]) & _MASK32
            s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & _MASK32
            hh, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + temp1) & _MASK32,
                c,
                b,
                a,
                (temp1 + temp2) & _MASK32,
            )
        h = [
            (h[0] + a) & _MASK32,
            (h[1] + b) & _MASK32,
            (h[2] + c) & _MASK32,
            (h[3] + d) & _MASK32,
            (h[4] + e) & _MASK32,
            (h[5] + f) & _MASK32,
            (h[6] + g) & _MASK32,
            (h[7] + hh) & _MASK32,
        ]
    return b"".join(word.to_bytes(4, "big") for word in h)


def sha512(data: bytes) -> bytes:
    """SHA-512 (FIPS 180-4)."""
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\x00" * ((-len(padded) - 16) % 128)
    padded += bit_length.to_bytes(16, "big")

    h = [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ]
    for offset in range(0, len(padded), 128):
        block = padded[offset : offset + 128]
        w = [int.from_bytes(block[i : i + 8], "big") for i in range(0, 128, 8)]
        for i in range(16, 80):
            s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK64)

        a, b, c, d, e, f, g, hh = h
        for i in range(80):
            s1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + s1 + ch + _SHA512_K[i] + w[i]) & _MASK64
            s0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & _MASK64
            hh, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + temp1) & _MASK64,
                c,
                b,
                a,
                (temp1 + temp2) & _MASK64,
            )
        h = [
            (h[0] + a) & _MASK64,
            (h[1] + b) & _MASK64,
            (h[2] + c) & _MASK64,
            (h[3] + d) & _MASK64,
            (h[4] + e) & _MASK64,
            (h[5] + f) & _MASK64,
            (h[6] + g) & _MASK64,
            (h[7] + hh) & _MASK64,
        ]
    return b"".join(word.to_bytes(8, "big") for word in h)


_RMD_R_LEFT = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13,
)
_RMD_R_RIGHT = (
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11,
)
_RMD_S_LEFT = (
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6,
)
_RMD_S_RIGHT = (
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11,
)


def _rmd_f(round_index: int, x: int, y: int, z: int) -> int:
    if round_index == 0:
        return x ^ y ^ z
    if round_index == 1:
        return (x & y) | (~x & z)
    if round_index == 2:
        return (x | ~y) ^ z
    if round_index == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


_RMD_K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 as specified by Dobbertin, Bosselaers and Preneel."""
    bit_length = len(data) * 8
    padded = data + b"\x80"
    padded += b"\x00" * ((-len(padded) - 8) % 64)
    padded += bit_length.to_bytes(8, "little")

    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        words = [int.from_bytes(block[i : i + 4], "little") for i in range(0, 64, 4)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            round_index = j // 16
            tl = (
                _rotl32(
                    (
                        al
                        + _rmd_f(round_index, bl, cl, dl)
                        + words[_RMD_R_LEFT[j]]
                        + _RMD_K_LEFT[round_index]
                    )
                    & _MASK32,
                    _RMD_S_LEFT[j],
                )
                + el
            ) & _MASK32
            al, el, dl, cl, bl = el, dl, _rotl32(cl, 10), bl, tl
            tr = (
                _rotl32(
                    (
                        ar
                        + _rmd_f(4 - round_index, br, cr, dr)
                        + words[_RMD_R_RIGHT[j]]
                        + _RMD_K_RIGHT[round_index]
                    )
                    & _MASK32,
                    _RMD_S_RIGHT[j],
                )
                + er
            ) & _MASK32
            ar, er, dr, cr, br = er, dr, _rotl32(cr, 10), br, tr
        temp = (h1 + cl + dr) & _MASK32
        h1 = (h2 + dl + er) & _MASK32
        h2 = (h3 + el + ar) & _MASK32
        h3 = (h4 + al + br) & _MASK32
        h4 = (h0 + bl + cr) & _MASK32
        h0 = temp
    return b"".join(word.to_bytes(4, "little") for word in (h0, h1, h2, h3, h4))


def hmac(hash_function: HashFunction, block_size: int, key: bytes, message: bytes) -> bytes:
    """HMAC as specified by RFC 2104."""
    if len(key) > block_size:
        key = hash_function(key)
    key = key.ljust(block_size, b"\x00")
    inner = bytes(byte ^ 0x36 for byte in key)
    outer = bytes(byte ^ 0x5C for byte in key)
    return hash_function(outer + hash_function(inner + message))


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac(sha256, 64, key, message)


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac(sha512, 128, key, message)
