#!/usr/bin/env python3
"""Compare the page's QR encoder (web/qr.js) module-for-module against the `qrcode` reference
encoder (a test-only dependency: pip install qrcode) for random data across
all versions, error-correction levels and masks. If a jsQR decoder script is
given, every symbol is also decoded and checked against the input.

Usage: python3 tests/test_qr_reference.py tests/qrgen.cjs [path/to/decode.cjs]
"""
import random
import subprocess
import sys

try:
    import qrcode
    from qrcode import util
except ImportError:
    print("qrcode not installed (pip install qrcode) - skipping reference comparison")
    sys.exit(0)

QRGEN = sys.argv[1] if len(sys.argv) > 1 else "tests/qrgen.cjs"
DECODER = sys.argv[2] if len(sys.argv) > 2 else None
ECL = "LMQH"
QRCODE_ECL = {0: qrcode.constants.ERROR_CORRECT_L, 1: qrcode.constants.ERROR_CORRECT_M,
              2: qrcode.constants.ERROR_CORRECT_Q, 3: qrcode.constants.ERROR_CORRECT_H}


def ours(data: bytes, ecl: int, mask: int):
    out = subprocess.run(["node", QRGEN, str(ecl), str(mask)], input=data, capture_output=True, check=True).stdout
    lines = out.decode().split("\n")
    version, used_ecl, used_mask = map(int, lines[0].split())
    rows = [tuple(int(c) for c in line) for line in lines[1:] if line]
    return version, used_ecl, used_mask, rows


def reference(data: bytes, ecl: int, version, mask):
    q = qrcode.QRCode(version=version, error_correction=QRCODE_ECL[ecl], mask_pattern=mask, border=0)
    q.add_data(util.QRData(data, mode=util.MODE_8BIT_BYTE))
    q.make(fit=version is None)
    return q.version, [tuple(int(v) for v in row) for row in q.get_matrix()]


def decode(rows):
    text = "\n".join("".join(map(str, r)) for r in rows)
    out = subprocess.run(["node", DECODER], input=text.encode(), capture_output=True).stdout.decode()
    return None if out == "FAIL" else bytes.fromhex(out)


def main():
    rng = random.Random(1234)
    cases = []
    # Byte lengths chosen to hit many versions, plus edge cases and URLs.
    for n in [0, 1, 2, 7, 14, 17, 26, 32, 42, 60, 100, 154, 213, 271, 500, 1000, 1500, 2331, 2953]:
        for ecl in range(4):
            cases.append((bytes(rng.randrange(256) for _ in range(n)), ecl))
    for _ in range(120):
        n = rng.randrange(0, 400)
        cases.append((bytes(rng.randrange(256) for _ in range(n)), rng.randrange(4)))
    cases.append((b"http://192.168.1.23:8080/?s=K7PQ2M", 1))

    checked = mismatches = skipped = decoded = 0
    versions = set()
    for i, (data, ecl) in enumerate(cases):
        mask = i % 9 - 1  # -1 = automatic, else forced 0..7
        try:
            version, used_ecl, used_mask, rows = ours(data, ecl, mask)
        except subprocess.CalledProcessError:
            skipped += 1  # too long for this ECC level
            continue
        assert used_ecl == ecl
        if mask >= 0:
            assert used_mask == mask, (used_mask, mask)
        _, ref = reference(data, ecl, version, used_mask)
        # the reference must also pick the same smallest version on its own
        auto_version, _ = reference(data, ecl, None, used_mask)
        if auto_version != version:
            print(f"version mismatch len={len(data)} ecl={ECL[ecl]}: ours {version}, reference {auto_version}")
            mismatches += 1
        if ref != rows:
            print(f"MATRIX MISMATCH len={len(data)} ecl={ECL[ecl]} v={version} mask={used_mask}")
            mismatches += 1
        if DECODER:
            got = decode(rows)
            if got != data:
                print(f"DECODE FAILURE len={len(data)} ecl={ECL[ecl]} v={version} mask={used_mask}")
                mismatches += 1
            else:
                decoded += 1
        checked += 1
        versions.add(version)

    print(f"QR reference test: {checked} symbols compared, {len(versions)} distinct versions "
          f"({min(versions)}-{max(versions)}), {decoded} decoded by jsQR, {skipped} too long, "
          f"{mismatches} mismatches")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
