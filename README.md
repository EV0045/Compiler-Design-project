# Constant-Time Security Transformation Pass

## 1. Project Overview

The Constant-Time Security Transformation Pass is a compiler-design project focused on detecting and transforming selected code patterns that can introduce timing side channels.

A timing side channel occurs when execution behaviour, such as branches or memory accesses, depends on secret data. An attacker may use timing differences to infer sensitive information.

The project analyses secrecy information, detects potential violations, applies supported LLVM IR transformations, and checks the transformed code using static verification and regression tests.

## 2. Objectives

- Identify secret and public values.
- Propagate secrecy information through program operations.
- Detect selected secret-dependent operations.
- Transform supported secret-dependent branches and constant-array lookups.
- Verify generated LLVM IR.
- Test functional correctness using unit and regression tests.

## 3. Architecture

The main components are:

1. **Secrecy Labeller** — assigns secrecy labels to inputs and values.
2. **Taint Engine** — propagates secrecy information through operations.
3. **Violation Detector** — identifies supported patterns that may cause timing leaks.
4. **Constant-Time Transformer** — rewrites supported patterns into alternative LLVM IR operations.
5. **Post-Transformation Verification** — reanalyses transformed code and checks for supported violations.

The project also contains benchmark kernels and automated test scripts.

## 4. Implementation

The implementation is primarily C++ and Python and uses LLVM IR for program analysis and transformation.

Important source files:

- `src/SecrecyLabeller.cpp`
- `src/TaintEngine.cpp`
- `src/ViolationDetector.cpp`
- `src/ConstantTimeTransformer.cpp`
- `src/PassRegistration.cpp`
- `src/member3_pipeline.cpp`

Python tests are located in `tests/`. Benchmark kernels and their generated LLVM IR are located in `benchmarks/kernels/`.

## 5. Supported Transformations

The current implementation includes:

- Transformation of supported secret-dependent branch patterns into select-based operations.
- Transformation of supported secret-indexed constant-array lookups into comparison and mask-based operations.
- Static verification after transformation.

Transformation support depends on the input IR structure and the conditions implemented by the pass.

## 6. Testing and Verified Results

The latest recorded verification produced these results:

| Test | Result |
|---|---|
| Python unit tests | 29 passed |
| Regression tests | 4,268 cases, 0 mismatches |
| LLVM IR verification | All three generated output files passed |
| AES S-box pipeline | Transformation and static verification reported success |
| memcmp pipeline | Ran successfully; no transformation was made |
| mod_exp pipeline | Ran successfully; no transformation was made |

The regression tests compare program outputs for the tested cases. These results support functional correctness for those cases but do not prove constant-time execution for every input or on every processor.

## 7. Build and Run

Build the project:

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

Run the Python unit tests:

```bash
python3 -m pytest tests/ -v
```

Run the regression tests:

```bash
python3 scripts/regression_test.py --random 2000
```

Run the pipeline on a benchmark:

```bash
python3 scripts/run_pipeline.py benchmarks/kernels/aes_sbox.c
```

Verify generated LLVM IR:

```bash
opt -passes=verify benchmarks/kernels/aes_sbox_out.ll -disable-output
```

The pipeline accepts a C source filename. Check its output messages to determine whether a transformation was actually applied.

## 8. Limitations

The current implementation does not transform every possible secret-dependent branch or memory access. In the latest recorded runs, `memcmp` and `mod_exp` completed without pipeline errors but reported that no transformation was made.

Functional regression tests and LLVM IR verification do not, by themselves, prove constant-time behaviour. Additional analysis and controlled native performance experiments are needed to assess generated machine code and performance overhead.

## 9. Project Structure

```text
.
├── benchmarks/kernels/
├── include/
├── src/
├── scripts/
├── tests/
├── docs/
├── results/
├── CMakeLists.txt
└── README.md
```

## 10. Conclusion

The project provides an LLVM-based foundation for secrecy analysis, violation detection, selected constant-time transformations, and automated verification. Its current results demonstrate passing tests and a working transformation for supported patterns, while broader transformation coverage and performance evaluation remain areas for further work.
