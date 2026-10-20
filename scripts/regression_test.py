#!/usr/bin/env python3
"""Functional regression test (Member 1, Week 3).

Builds each baseline kernel and its transformed counterpart as shared
libraries, runs both on the same inputs via ctypes, and asserts identical
outputs. Writes metrics to results/regression_metrics.json.

Transformed source for kernel X is the first of these that exists:
  1. <transformed-dir>/X_out.ll   (output of scripts/run_pipeline.py)
  2. benchmarks/reference/X_ct.c  (hand-written constant-time reference)

Usage:
  python3 scripts/regression_test.py [--transformed-dir DIR] [--random N]
"""
import argparse
import ctypes
import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNELS = ROOT / "benchmarks" / "kernels"
REFERENCE = ROOT / "benchmarks" / "reference"
RESULTS = ROOT / "results"

M64 = (1 << 64) - 1


def build_lib(src: Path, out: Path):
    subprocess.run(
        ["clang", "-O1", "-shared", "-fPIC", str(src), "-o", str(out)],
        check=True, capture_output=True, text=True,
    )
    return ctypes.CDLL(str(out))


def find_transformed(name: str, tdir: Path):
    ll = tdir / f"{name}_out.ll"
    if ll.exists() and ll.stat().st_size > 0:
        return ll, "pass-output"
    ref = REFERENCE / f"{name}_ct.c"
    if ref.exists() and ref.stat().st_size > 0:
        return ref, "reference"
    return None, None


# ---- per-kernel test cases: each returns (n_cases, list_of_mismatches) ----

def test_aes(base, trans, rng, n_random):
    for lib in (base, trans):
        lib.aes_sbox.argtypes = [ctypes.c_uint8]
        lib.aes_sbox.restype = ctypes.c_uint8
    bad = [i for i in range(256) if base.aes_sbox(i) != trans.aes_sbox(i)]
    return 256, [f"input={i}" for i in bad]


def test_memcmp(base, trans, rng, n_random):
    for lib in (base, trans):
        lib.secret_memcmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        lib.secret_memcmp.restype = ctypes.c_int
    cases = [(b"", b"", 0), (b"a", b"a", 1), (b"a", b"b", 1),
             (b"apple", b"axe\0\0", 5), (b"same", b"same", 4)]
    for _ in range(n_random):
        n = rng.randint(1, 64)
        a = bytes(rng.randrange(1, 256) for _ in range(n))
        b = bytearray(a)
        if rng.random() < 0.5:                       # force a mismatch
            b[rng.randrange(n)] = rng.randrange(1, 256)
        cases.append((a, bytes(b), n))
    bad = []
    for a, b, n in cases:
        # baseline returns 0/1; compare only zero vs non-zero to allow
        # constant-time versions that return a different non-zero value.
        if (base.secret_memcmp(a, b, n) != 0) != (trans.secret_memcmp(a, b, n) != 0):
            bad.append(f"a={a!r} b={b!r} n={n}")
    return len(cases), bad


def test_modexp(base, trans, rng, n_random):
    for lib in (base, trans):
        lib.mod_exp.argtypes = [ctypes.c_uint64] * 3
        lib.mod_exp.restype = ctypes.c_uint64
    cases = [(2, 0, 7), (2, 1, 7), (0, 5, 7), (5, 3, 1), (3, 200, 1000003),
             (2, M64 >> 1, 1000003), (7, 13, 2)]
    for _ in range(n_random):
        # mod < 2^32 so (result*base) cannot overflow in the baseline either
        cases.append((rng.randrange(0, 1 << 32), rng.randrange(0, 1 << 20),
                      rng.randrange(1, 1 << 32)))
    bad = [f"base={b} exp={e} mod={m}" for b, e, m in cases
           if base.mod_exp(b, e, m) != trans.mod_exp(b, e, m)]
    return len(cases), bad


TESTS = {
    "aes_sbox": test_aes,
    "memcmp": test_memcmp,
    "mod_exp": test_modexp,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transformed-dir", type=Path, default=KERNELS,
                    help="directory holding <kernel>_out.ll files")
    ap.add_argument("--random", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    metrics = {"seed": args.seed, "random_cases": args.random, "kernels": {}}
    failed = False

    try:
        tmp_ctx = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    except TypeError:
        tmp_ctx = tempfile.TemporaryDirectory()

    with tmp_ctx as tmp:
        tmp = Path(tmp)
        for name, fn in TESTS.items():
            entry = {}
            trans_src, kind = find_transformed(name, args.transformed_dir)
            if trans_src is None:
                entry["status"] = "SKIPPED (no transformed output or reference)"
                print(f"[SKIP] {name}")
                metrics["kernels"][name] = entry
                continue
            try:
                base = build_lib(KERNELS / f"{name}.c", tmp / f"{name}_base.dylib")
                trans = build_lib(trans_src, tmp / f"{name}_trans.dylib")
            except subprocess.CalledProcessError as e:
                entry["status"] = "BUILD FAILED"
                entry["error"] = e.stderr[-500:]
                print(f"[FAIL] {name}: build error\n{e.stderr}")
                failed = True
                metrics["kernels"][name] = entry
                continue

            t0 = time.time()
            n, bad = fn(base, trans, rng, args.random)
            entry.update(transformed_source=kind, cases=n, mismatches=len(bad),
                         status="PASS" if not bad else "FAIL",
                         seconds=round(time.time() - t0, 3))
            if bad:
                entry["examples"] = bad[:5]
                failed = True
            print(f"[{entry['status']}] {name}: {n} cases, {len(bad)} mismatches ({kind})")
            metrics["kernels"][name] = entry

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "regression_metrics.json"
    out.write_text(json.dumps(metrics, indent=2))
    print(f"Metrics written to {out.relative_to(ROOT)}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
