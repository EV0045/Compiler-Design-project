#!/usr/bin/env python3
"""Automated Performance Benchmark Suite (Member 4, Week 3).

Measures and compares execution time of baseline vs constant-time implementations
for the target security kernels:
  - aes_sbox (Cache lookup vs Masked 256-iteration scan)
  - memcmp   (Early-exit loop vs Bitwise accumulator scan)
  - mod_exp  (Variable ladder vs Fixed 64-iteration bitmask)

Computes slowdown factors, overhead percentages, and records results to:
  - results/performance_benchmarks.json
  - results/PERFORMANCE_REPORT.md

Usage:
  python3 scripts/benchmark.py [--iterations N]
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


def build_lib(src: Path, out: Path):
    cmd = ["clang", "-O2", "-shared"]
    if sys.platform != "win32":
        cmd.append("-fPIC")
    cmd.extend([str(src), "-o", str(out)])
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return ctypes.CDLL(str(out))


def find_constant_time(name: str):
    ll = KERNELS / f"{name}_out.ll"
    if ll.exists() and ll.stat().st_size > 0:
        return ll, "compiler_pass_transformed"
    ref = REFERENCE / f"{name}_ct.c"
    if ref.exists() and ref.stat().st_size > 0:
        return ref, "reference_constant_time"
    return None, None


def benchmark_aes(base_lib, ct_lib, iterations=2000000):
    for lib in (base_lib, ct_lib):
        lib.aes_sbox.argtypes = [ctypes.c_uint8]
        lib.aes_sbox.restype = ctypes.c_uint8

    inputs = [random.randint(0, 255) for _ in range(1000)]
    n_in = len(inputs)

    # Warmup
    for i in range(1000):
        base_lib.aes_sbox(inputs[i % n_in])
        ct_lib.aes_sbox(inputs[i % n_in])

    # Benchmark baseline
    t0 = time.perf_counter()
    for i in range(iterations):
        base_lib.aes_sbox(inputs[i % n_in])
    t_base = time.perf_counter() - t0

    # Benchmark constant-time
    t0 = time.perf_counter()
    for i in range(iterations):
        ct_lib.aes_sbox(inputs[i % n_in])
    t_ct = time.perf_counter() - t0

    overhead = ((t_ct - t_base) / t_base) * 100.0 if t_base > 0 else 0.0
    slowdown = (t_ct / t_base) if t_base > 0 else 1.0

    return {
        "iterations": iterations,
        "baseline_seconds": round(t_base, 6),
        "constant_time_seconds": round(t_ct, 6),
        "overhead_percentage": round(overhead, 2),
        "slowdown_factor": round(slowdown, 2),
    }


def benchmark_memcmp(base_lib, ct_lib, iterations=50000):
    for lib in (base_lib, ct_lib):
        lib.secret_memcmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        lib.secret_memcmp.restype = ctypes.c_int

    pairs = []
    for _ in range(100):
        n = 64
        a = bytes(random.randrange(1, 256) for _ in range(n))
        b = bytearray(a)
        if random.random() < 0.5:
            b[random.randrange(n)] = random.randrange(1, 256)
        pairs.append((a, bytes(b), n))

    n_pairs = len(pairs)

    # Warmup
    for i in range(500):
        a, b, n = pairs[i % n_pairs]
        base_lib.secret_memcmp(a, b, n)
        ct_lib.secret_memcmp(a, b, n)

    # Benchmark baseline
    t0 = time.perf_counter()
    for i in range(iterations):
        a, b, n = pairs[i % n_pairs]
        base_lib.secret_memcmp(a, b, n)
    t_base = time.perf_counter() - t0

    # Benchmark constant-time
    t0 = time.perf_counter()
    for i in range(iterations):
        a, b, n = pairs[i % n_pairs]
        ct_lib.secret_memcmp(a, b, n)
    t_ct = time.perf_counter() - t0

    overhead = ((t_ct - t_base) / t_base) * 100.0 if t_base > 0 else 0.0
    slowdown = (t_ct / t_base) if t_base > 0 else 1.0

    return {
        "iterations": iterations,
        "buffer_size": 64,
        "baseline_seconds": round(t_base, 6),
        "constant_time_seconds": round(t_ct, 6),
        "overhead_percentage": round(overhead, 2),
        "slowdown_factor": round(slowdown, 2),
    }


def benchmark_mod_exp(base_lib, ct_lib, iterations=20000):
    for lib in (base_lib, ct_lib):
        lib.mod_exp.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
        lib.mod_exp.restype = ctypes.c_uint64

    triples = []
    for _ in range(100):
        base = random.randrange(2, 1 << 32)
        exp = random.randrange(1, 1 << 32)
        mod = random.randrange(3, 1 << 32) | 1
        triples.append((base, exp, mod))

    n_triples = len(triples)

    # Warmup
    for i in range(200):
        b, e, m = triples[i % n_triples]
        base_lib.mod_exp(b, e, m)
        ct_lib.mod_exp(b, e, m)

    # Benchmark baseline
    t0 = time.perf_counter()
    for i in range(iterations):
        b, e, m = triples[i % n_triples]
        base_lib.mod_exp(b, e, m)
    t_base = time.perf_counter() - t0

    # Benchmark constant-time
    t0 = time.perf_counter()
    for i in range(iterations):
        b, e, m = triples[i % n_triples]
        ct_lib.mod_exp(b, e, m)
    t_ct = time.perf_counter() - t0

    overhead = ((t_ct - t_base) / t_base) * 100.0 if t_base > 0 else 0.0
    slowdown = (t_ct / t_base) if t_base > 0 else 1.0

    return {
        "iterations": iterations,
        "exponent_bits": 64,
        "baseline_seconds": round(t_base, 6),
        "constant_time_seconds": round(t_ct, 6),
        "overhead_percentage": round(overhead, 2),
        "slowdown_factor": round(slowdown, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Constant-time performance benchmark")
    parser.add_argument("--scale", type=float, default=1.0, help="Scale iteration counts")
    args = parser.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    bench_data = {
        "suite": "Constant-Time Pass Performance Benchmark",
        "compiler": "LLVM/Clang",
        "optimization": "-O2",
        "kernels": {},
    }

    print("=" * 70)
    print("CONSTANT-TIME SECURITY PASS — PERFORMANCE BENCHMARK")
    print("=" * 70)

    try:
        td_ctx = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    except TypeError:
        td_ctx = tempfile.TemporaryDirectory()

    with td_ctx as td:
        tdp = Path(td)
        dll_ext = ".dll" if sys.platform == "win32" else ".so"

        # 1. AES S-box
        print("\n[1/3] Benchmarking AES S-box...")
        aes_base = build_lib(KERNELS / "aes_sbox.c", tdp / f"aes_base{dll_ext}")
        ct_src, ct_type = find_constant_time("aes_sbox")
        if not ct_src:
            print("  Warning: No constant-time AES source found, skipping.")
        else:
            aes_ct = build_lib(ct_src, tdp / f"aes_ct{dll_ext}")
            res = benchmark_aes(aes_base, aes_ct, int(2000000 * args.scale))
            res["source_type"] = ct_type
            bench_data["kernels"]["aes_sbox"] = res
            print(f"  Baseline:      {res['baseline_seconds']}s")
            print(f"  Constant-Time: {res['constant_time_seconds']}s")
            print(f"  Slowdown:      {res['slowdown_factor']}x (+{res['overhead_percentage']}%)")

        # 2. memcmp
        print("\n[2/3] Benchmarking memcmp...")
        mem_base = build_lib(KERNELS / "memcmp.c", tdp / f"mem_base{dll_ext}")
        ct_src, ct_type = find_constant_time("memcmp")
        if not ct_src:
            print("  Warning: No constant-time memcmp source found, skipping.")
        else:
            mem_ct = build_lib(ct_src, tdp / f"mem_ct{dll_ext}")
            res = benchmark_memcmp(mem_base, mem_ct, int(50000 * args.scale))
            res["source_type"] = ct_type
            bench_data["kernels"]["memcmp"] = res
            print(f"  Baseline:      {res['baseline_seconds']}s")
            print(f"  Constant-Time: {res['constant_time_seconds']}s")
            print(f"  Slowdown:      {res['slowdown_factor']}x (+{res['overhead_percentage']}%)")

        # 3. mod_exp
        print("\n[3/3] Benchmarking mod_exp...")
        exp_base = build_lib(KERNELS / "mod_exp.c", tdp / f"exp_base{dll_ext}")
        ct_src, ct_type = find_constant_time("mod_exp")
        if not ct_src:
            print("  Warning: No constant-time mod_exp source found, skipping.")
        else:
            exp_ct = build_lib(ct_src, tdp / f"exp_ct{dll_ext}")
            res = benchmark_mod_exp(exp_base, exp_ct, int(20000 * args.scale))
            res["source_type"] = ct_type
            bench_data["kernels"]["mod_exp"] = res
            print(f"  Baseline:      {res['baseline_seconds']}s")
            print(f"  Constant-Time: {res['constant_time_seconds']}s")
            print(f"  Slowdown:      {res['slowdown_factor']}x (+{res['overhead_percentage']}%)")

    # Output json
    out_file = RESULTS / "performance_benchmarks.json"
    with open(out_file, "w") as f:
        json.dump(bench_data, f, indent=2)
    print(f"\nSaved benchmark metrics to {out_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
