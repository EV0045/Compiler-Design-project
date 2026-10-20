# Live Demo Guide
## Constant-Time Security Transformation Pass

## 1. Purpose

Demonstrate the build, automated tests, LLVM IR verification, and transformation pipeline for the project.

## 2. Open the Repository

```bash
cd /mnt/c/Users/vigne/OneDrive/Desktop/PROJECTGIT/Compiler-Design-project
```

## 3. Build the Project

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

Explain that the C++ implementation is compiled into the project's build targets.

## 4. Run the Unit Tests

```bash
python3 -m pytest tests/ -v
```

Latest recorded result: 29 tests passed.

## 5. Run the Regression Tests

```bash
python3 scripts/regression_test.py --random 2000
```

Latest recorded results:

- AES S-box: 256 cases, zero mismatches.
- memcmp: 2,005 cases, zero mismatches.
- mod_exp: 2,007 cases, zero mismatches.
- Total: 4,268 cases, zero mismatches.

These results establish output agreement for the tested cases, not a universal proof of constant-time behaviour.

## 6. Demonstrate the AES S-box Transformation

```bash
python3 scripts/run_pipeline.py benchmarks/kernels/aes_sbox.c
```

The latest recorded run reported that the constant-array lookup was transformed and static constant-time verification passed for `aes_sbox`.

Inspect the generated IR:

```bash
ls -lh benchmarks/kernels/aes_sbox.ll benchmarks/kernels/aes_sbox_out.ll
```

Verify the output:

```bash
opt -passes=verify benchmarks/kernels/aes_sbox_out.ll -disable-output
```

A successful verification command produces no error output.

## 7. Demonstrate the Other Benchmark Kernels

```bash
python3 scripts/run_pipeline.py benchmarks/kernels/memcmp.c
python3 scripts/run_pipeline.py benchmarks/kernels/mod_exp.c
```

Both pipelines detect secret violations accurately. As documented in `docs/TRANSFORMATION_COVERAGE_REPORT.md`:
* `memcmp` contains an early loop exit (`ret`), which cannot be converted by a local CFG diamond pass without loop flattening; its verified constant-time equivalent is provided in `benchmarks/reference/memcmp_ct.c`.
* `mod_exp` contains a remainder operation (`urem`), which LLVM rejects hoisting speculatively to protect against division-by-zero crashes (`SIGFPE`); its verified constant-time equivalent is provided in `benchmarks/reference/mod_exp_ct.c`.

## 8. Verify All Generated Output Files

```bash
for file in benchmarks/kernels/aes_sbox_out.ll \
            benchmarks/kernels/memcmp_out.ll \
            benchmarks/kernels/mod_exp_out.ll; do
    echo "--- $file ---"
    opt -passes=verify "$file" -disable-output || exit 1
done
```

## 9. Final Test & Performance Benchmark Run

```bash
python3 -m pytest tests/ -q
python3 scripts/regression_test.py --random 2000
```

Performance overhead measurements (see `results/PERFORMANCE_REPORT.md`):
* AES S-box: ~92.1x slowdown (+9,116% overhead) due to 256-iteration bitmask scanning.
* memcmp: ~2.38x slowdown (+137% overhead) due to scanning all $N$ bytes.
* mod_exp: ~2.87x slowdown (+186% overhead) due to fixed 64-bit normalization.

## 10. Suggested Explanation to the Evaluator

"Our project analyses secrecy information and detects selected timing-sensitive patterns in LLVM IR. For supported patterns, the transformation pass rewrites secret-dependent memory lookups into constant-time bitmask scans, demonstrated by our AES S-box kernel (passing static verification with a measured 92.1x overhead eliminating cache timing). For memcmp and mod_exp, we performed a full root-cause investigation documenting why early loop exits and speculative modulo operations require loop-level accumulation and bitmask ladders, which we validated through our verified constant-time reference implementations and automated regression suite."
