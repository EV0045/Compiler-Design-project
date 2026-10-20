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

In the latest recorded runs, both pipelines completed, but neither kernel was transformed. State this limitation clearly during the demonstration.

## 8. Verify All Generated Output Files

```bash
for file in benchmarks/kernels/aes_sbox_out.ll \
            benchmarks/kernels/memcmp_out.ll \
            benchmarks/kernels/mod_exp_out.ll; do
    echo "--- $file ---"
    opt -passes=verify "$file" -disable-output || exit 1
done
```

## 9. Final Test Run

```bash
python3 -m pytest tests/ -q
python3 scripts/regression_test.py --random 2000
```

Use the current terminal output as the evidence for the live demonstration.

## 10. Suggested Explanation to the Evaluator

"Our project analyses secrecy information and detects selected timing-sensitive patterns in LLVM IR. For supported patterns, the transformation pass rewrites secret-dependent branches or constant-array lookups. We validate the implementation using unit tests, regression tests, and LLVM IR verification. The current AES S-box example demonstrates a successful transformation. The memcmp and mod_exp examples currently complete without transformation, which is a known limitation. Passing functional tests does not alone prove constant-time execution, so broader security verification and performance evaluation remain future work."
