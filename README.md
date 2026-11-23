**Educational lab only: not for production, not for real secrets, no P2P network.**

# crypto-lab

Elliptic-curve cryptography built from scratch in Python 3.12, with no cryptographic
dependencies. The repository exists to show the arithmetic and the failure modes, not to
protect anything. Every primitive is checked against official test vectors and, where
applicable, against OpenSSL.

Author: Iker Abad. License: MIT.

## What is inside

| Area | Implementation |
|---|---|
| Big integers | Unsigned base-2^64 limbs, schoolbook multiplication, Knuth Algorithm D division, extended Euclid inverse, square-and-multiply |
| Prime field | 256-bit Montgomery representation, CIOS multiplication, addition, subtraction, inversion, square root, batch inversion |
| Curves | secp256k1; NIST P-256 is included only to run the RFC 6979 vectors |
| Point arithmetic | Affine and Jacobian coordinates, mixed addition, doubling, batch conversion |
| Scalar multiplication | Affine double-and-add baseline, Jacobi double-and-add, sliding window, fixed-iteration Montgomery ladder |
| Encoding | SEC1 compressed and uncompressed points, DER ECDSA signatures, SEC1 private-key and SubjectPublicKeyInfo PEM, Base58Check |
| Hashing | SHA-256, SHA-512, RIPEMD-160, HMAC (RFC 2104), implemented in this repository |
| ECDSA | Key generation, deterministic RFC 6979 signing, verification, DER signatures, low-S normalisation and malleability checks |
| HD keys | BIP32 master key and one child level, hardened and non-hardened, xprv/xpub serialisation |

## Non-goals

- This is not a library. Do not use it to protect keys, signatures, wallets or traffic.
- There is no secret management, no side-channel hardening at the machine-code level, no
  network protocol and no P2P layer.
- The implementation favours clarity over speed. Python cannot provide hard constant-time
  guarantees, and the timing countermeasure below is an algorithm-level demonstration.
- Only secp256k1 is exposed as a target curve. P-256 appears solely because RFC 6979
  publishes its official ECDSA vectors there.

## Quick start

```bash
py -3.12 -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
pytest -q
ruff check .
ruff format --check .
mypy src
```

On Unix the activation command is `source .venv/bin/activate`.

Useful scripts:

```bash
python scripts/benchmark.py
python scripts/timing_demo.py
python scripts/check_external_vectors.py
```

The last script downloads RFC 4231, RFC 6979, BIP32 and the Wycheproof corpus, verifies the
pinned source hash, checks that every vendored Wycheproof case and public key is identical
to its upstream test object, and runs all 476 secp256k1/SHA-256 cases. It is also the second
CI job.
`python scripts/vendor_wycheproof.py --check` regenerates the 75-case subset in memory and
confirms that the committed subset and provenance files still match.

## Test vectors

| Source | Coverage |
|---|---|
| RFC 4231 | Seven HMAC-SHA256 cases, including long keys, long messages and truncated output; HMAC-SHA512 is checked against the same document for BIP32 |
| RFC 6979 Appendix A.2.5 | P-256/SHA-256 public key, deterministic nonces, `r`, `s` for both official messages, plus deterministic signing |
| BIP32 test vectors 1, 2 and 3 | Master key and first child, including hardened and non-hardened derivation and leading-zero retention |
| SEC 2 | secp256k1 field, order, generator and curve equation; known small multiples of G |
| Wycheproof | 75-case vendored subset, 30 valid and 45 invalid, covering all 18 flag combinations; the external-vector job checks the pinned source hash and runs all 476 cases |

The vendored files live in `vectors/`. The external checker
(`scripts/check_external_vectors.py`) records the official URLs it downloads and re-checks
the vendored values against them on every CI run. secp256k1 parameters come from SEC 2
(https://www.secg.org/sec2-v2.pdf).

## Big integers

`crypto_lab.bigint.BigInt` stores a non-negative integer as a little-endian tuple of
64-bit limbs. Python's `int` is used only as a limb-sized accumulator; the algorithms are
implemented over limbs:

- addition and subtraction with carry and borrow;
- schoolbook multiplication, `O(n^2)`;
- division with Knuth's Algorithm D, including normalization and the add-back step;
- modular inverse with the extended Euclidean algorithm, keeping the coefficient reduced
  modulo the modulus;
- modular exponentiation by square-and-multiply.

The test suite fuzzes all of these against Python integers with Hypothesis, including
limb-boundary values at 64, 128, 256 and 512 bits.

`crypto_lab.field.MontgomeryField` is the performance-critical layer. It uses four
64-bit limbs, Montgomery representation `aR mod p` with `R = 2^256`, and a CIOS
multiplication loop. Inversion is `a^(p-2)`, square roots use `p ≡ 3 (mod 4)`, and batch
inversion uses the usual prefix-product trick.

## Curve arithmetic

`Curve` implements the short Weierstrass equation

```
y^2 = x^3 + a*x + b  (mod p)
```

The affine formulas perform one field inversion per point operation. The Jacobian formulas
keep `Z` and perform one inversion at the end, when converting back to affine coordinates.
Doubling has a specialised `a = 0` path for secp256k1 and a general path for P-256. Addition
uses the standard Jacobian and mixed Jacobian-affine formulas.

Measured with `python scripts/benchmark.py` on 2026-11-23. Hardware: AMD Ryzen 9 5900X
(12 cores / 24 threads), 32 GB DDR4-3600 CL16, Windows 11 build 10.0.26300, CPython 3.12.10.

| Scalar bits | Affine double-and-add | Jacobi double-and-add | Sliding window (w=4) | Montgomery ladder |
|---:|---:|---:|---:|---:|
| 32 | 0.2586 s | 0.0143 s | 0.0181 s | 0.0864 s |
| 64 | 0.4676 s | 0.0237 s | 0.0247 s | 0.0923 s |
| 128 | 0.9245 s | 0.0374 s | 0.0395 s | 0.0992 s |
| 256 | 1.8566 s | 0.0653 s | 0.0589 s | 0.1158 s |

The 256-bit affine result is roughly 28 times slower than Jacobi. At 256 bits the sliding
window beats plain Jacobi double-and-add because it trades precomputation for fewer
additions. The ladder is slower by design: it executes a fixed number of additions and
doublings and uses branch-free formulas, so it does more work than a variable-time method.

Per-operation medians from the same run:

| Operation | Median time |
|---|---:|
| Field addition | 1.90 us |
| Field subtraction | 2.40 us |
| Field multiplication | 8.10 us |
| Field inversion | 4.53 ms |
| Field square root | 4.49 ms |
| Point doubling (affine) | 4.63 ms |
| Point doubling (Jacobi) | 146.00 us |
| Point addition (affine) | 4.62 ms |
| Point addition (Jacobi) | 224.30 us |
| Mixed addition (Jacobi + affine) | 174.70 us |
| Scalar multiplication (sliding w=4, 64-bit scalar) | 26.46 ms |
| Scalar multiplication (ladder, 64-bit scalar) | 93.99 ms |
| ECDSA sign | 119.56 ms |
| ECDSA verify | 338.33 ms |
| ECDSA recover public key | 587.06 ms |
| SHA-256 (1 KiB) | 2.57 ms |
| HMAC-SHA256 (1 KiB) | 3.01 ms |
| BIP32 master from seed | 778.50 us |
| BIP32 first hardened child | 119.28 ms |

For the raw arithmetic layer, 256-bit modular multiplication measured about 16.4 us with
schoolbook multiplication plus Knuth division, against 8.4 us with Montgomery
multiplication. These are single-machine medians, not a portable benchmark suite.

## Scalar multiplication and the timing attack

The variable-time methods are deliberately kept:

- `double_and_add` scans the scalar from the most significant bit and performs an addition
  only when the current bit is one.
- `sliding_window` precomputes odd multiples and processes a variable number of bits per
  iteration.

Both have data-dependent control flow. The classic timing attack on this shape is described
by Kocher in “Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other
Systems” (CRYPTO 1996). The number and pattern of point additions depend on the secret
scalar. A local attacker can measure it directly. A remote attacker can use repeated
measurements and statistical tests, as in Brumley and Boneh's remote timing work. In ECDSA,
a biased or partially known nonce is worse than a timing leak about the private key: nonce
recovery leads to private-key recovery. The relevant lattice and hidden-number techniques
are outside a first-year course, but the consequence is simple: the nonce must not leak.

`scripts/timing_demo.py` makes the leak visible without claiming to be a real attack:

| Scalar | Algorithm | Doublings | Additions | Mixed additions | Inversions |
|---|---|---:|---:|---:|---:|
| one bit set | double-and-add | 256 | 0 | 0 | 1 |
| one bit set | Montgomery ladder | 256 | 256 | 0 | 1 |
| n-1 | double-and-add | 256 | 0 | 190 | 1 |
| n-1 | Montgomery ladder | 256 | 256 | 0 | 1 |

The same run measured about 0.047 s for double-and-add with one set bit and 0.080 s with
`n-1`, while the ladder stayed near 0.117-0.122 s. The operation counts are the reliable
result. Wall-clock numbers on CPython and a general-purpose OS are noisy.

The countermeasure used by ECDSA is the Montgomery ladder:

- exactly 256 iterations for a 256-bit scalar, one doubling and one addition per iteration;
- conditional swap implemented with arithmetic masks (`FieldElement.select`), not an
  `if bit:` branch;
- branch-free Jacobian doubling: the formula is always evaluated and the point at infinity
  is selected arithmetically when `Z = 0` or `Y = 0`;
- ladder addition uses a branch-free path that handles the infinity cases by selection and
  relies on the ladder invariant that the two finite states are distinct;
- the scalar is reduced modulo the group order;
- ECDSA uses RFC 6979 deterministic nonces, removing the RNG failure mode, and low-S
  normalisation.

This removes the obvious Hamming-weight branch from the scalar loop. It does **not** make
the code constant-time in the hardware sense. CPython's interpreter, object allocation,
garbage collection, integer normalization and memory access patterns are outside the
control of this code. A production implementation needs fixed-time field arithmetic,
fixed-time point formulas, a constant-time RNG and a much more careful threat model. The
README says this on purpose: a lab that claims constant-time Python would be lying.

## Serialization

SEC1 point encodings:

- uncompressed: `0x04 || X || Y`, 65 bytes;
- compressed: `0x02` or `0x03` followed by `X`, 33 bytes, with the prefix carrying the
  parity of `Y`;
- decompression solves `y^2 = x^3 + a*x + b` and chooses the square root with the requested
  parity.

ECDSA signatures are encoded as DER `SEQUENCE { INTEGER r, INTEGER s }`. The decoder is
strict: it rejects negative integers, non-minimal lengths, non-minimal integers, trailing
data and zero values. That strictness is what makes the malformed Wycheproof cases fail for
the right reason.

Private keys are written as SEC1 `ECPrivateKey` with the named curve and public key
embedded. Public keys are written as `SubjectPublicKeyInfo`. Both are wrapped in PEM.

## ECDSA and malleability

`sign` uses RFC 6979 with HMAC-SHA256. The default is low-S: if `s > n/2`, it replaces `s`
with `n - s`. `verify` accepts high-S values by default because that is what standard ECDSA
verifiers do, and it has an explicit `low_s=True` mode for the stricter policy.

Malleability is easy to demonstrate:

- take a valid `(r, s)`;
- compute `s' = n - s`;
- `(r, s')` is also a valid ECDSA signature for the same message and key.

The tests verify both versions, check that `low_s=True` rejects the high-S version, and
check that normalising returns the original low-S signature. This is why Bitcoin-style code
normalises signatures before accepting them.

### Public-key recovery

`recover_public_key` reconstructs the signing key from `(message, r, s, recovery_id)`. The
recovery id has two bits:

- bit 1 chooses the ephemeral x-coordinate: `r` for ids 0 and 1, `r + n` for ids 2 and 3;
- bit 0 chooses the parity of the ephemeral point `R`.

The candidate point `R` is decompressed from `x`, then:

```
Q = r^(-1) * (s*R - z*G)
```

where `z` is the truncated message hash. The function validates that the recovered key is
on the curve and that it verifies the signature. `find_recovery_id` tries the four possible
ids and returns the one that matches a known public key. The test vectors are four valid
Wycheproof cases, including one that needs `recovery_id = 3` (`r + n`), and the recovered
coordinates are compared with the original Wycheproof public key.

The recovery id is not part of an ECDSA signature. A protocol that uses recovery must
transmit it separately, and a signature can have more than one syntactically valid recovery
id unless the verifier checks the expected key. The function deliberately checks the
resulting key against the signature instead of trusting the id alone.

## OpenSSL interoperability

The test suite creates a secp256k1 key with this code, writes PEM files and a message, then
runs OpenSSL in both directions:

```bash
# our signature, OpenSSL verifier
openssl dgst -sha256 -verify public.pem -signature our.der message.bin

# OpenSSL signer, our verifier
openssl dgst -sha256 -sign private.pem -out openssl.der message.bin
```

It also asks OpenSSL to verify the high-S malleable variant, and checks that OpenSSL rejects
a tampered message. OpenSSL 3.4.1 was used during development. The tests fail, rather than
skip, if `openssl` is not on `PATH`; the CI test job checks that it is installed.

## HMAC and BIP32

SHA-256, SHA-512 and RIPEMD-160 are implemented in `hashing.py`, with HMAC built on top of
them. BIP32 uses:

```
I = HMAC-SHA512(key = "Bitcoin seed", data = seed)
IL = I[0:32]   (master private key)
IR = I[32:64]  (chain code)
```

For a child:

- hardened: `data = 0x00 || ser256(k_par) || ser32(i)`;
- non-hardened: `data = serP(K_par) || ser32(i)`;
- `I = HMAC-SHA512(chain_code, data)`;
- child key `= (IL + k_par) mod n`, child chain code `= IR`;
- invalid when `IL >= n` or the child key is zero.

The implementation stops at the first child level, as requested. xprv/xpub serialisation
uses the mainnet version bytes, depth, parent fingerprint, child number, chain code and
Base58Check. The three BIP32 test vectors check both hardened and non-hardened first
children, including the leading-zero cases.

## CI

`.github/workflows/ci.yml` has two jobs:

1. `test`: Python 3.12, install the package with development extras, run `ruff check`,
   `ruff format --check`, `mypy src` and `pytest -q`, including the OpenSSL interop tests.
2. `external-vectors`: download the current RFC/BIP/Wycheproof material, verify the pinned
   Wycheproof source hash, confirm that the 75 vendored cases are unchanged upstream, and
   run `scripts/check_external_vectors.py`. The test job runs the vendored subset on every
   push; the external job is the one that exercises all 476 external ECDSA cases.

## Acceptance checklist

| Criterion | Status |
|---|---|
| Big-integer arithmetic with add, subtract, multiply, division, extended Euclid inverse, fast exponentiation | Yes, fuzzed against Python integers |
| secp256k1 point addition in affine and Jacobi coordinates | Yes, cross-checked against each other and known multiples |
| Scalar multiplication by double-and-add and sliding window | Yes, plus the fixed-iteration ladder |
| Timing attack documented and countermeasure applied | Yes, see above and `scripts/timing_demo.py` |
| Compressed and uncompressed point serialization | Yes, SEC1 |
| ECDSA key generation, sign, verify, malleability check | Yes, RFC 6979 and low-S |
| Public-key recovery from a signature | Yes, four valid Wycheproof cases, including `recovery_id = 3` |
| Group law property tests | Yes, Hypothesis checks associativity, identity, inverse and commutativity |
| HMAC-SHA256 and BIP32-style derivation, first layer | Yes, RFC 4231 and BIP32 vectors 1-3 |
| Official RFC/BIP vectors pass | Yes, local tests and external-vector job |
| Wycheproof subset is versioned with provenance and SHA-256 | Yes, 75 cases, pinned upstream hash |
| Our signature verified by OpenSSL and vice versa | Yes, `tests/test_openssl.py` |
| Tests pass with zero skips | Yes, 105 passed, 0 skipped |
| README documents timing attack and countermeasure | Yes |
| Out-of-scope warning in the first line | Yes |

## Repository layout

```
src/crypto_lab/
  bigint.py       arbitrary-precision unsigned integers
  field.py        Montgomery prime-field arithmetic
  curves.py       affine and Jacobian points, secp256k1, P-256
  scalarmult.py   double-and-add, sliding window, Montgomery ladder
  encoding.py     SEC1, DER, PEM, Base58Check
  hashing.py      SHA-256, SHA-512, RIPEMD-160, HMAC
  rfc6979.py      deterministic ECDSA nonces
  ecdsa.py        key generation, signing, verification, recovery, low-S
  bip32.py        master key and first-level child derivation
tests/            unit, property, recovery and OpenSSL interoperability tests
vectors/          vendored official vectors, Wycheproof subset and provenance
scripts/          benchmark, timing demo, external-vector checker, Wycheproof vendor
```

## License

MIT. See `LICENSE`.
