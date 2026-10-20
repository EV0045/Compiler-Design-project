# Final Project Evidence

## Project
Constant-Time Security Transformation Pass

## Implemented Components
- Secrecy Labeller
- Taint Engine
- Violation Detector
- Constant-Time Transformer
- Post-transformation analysis and verification
- Benchmark kernels and automated regression testing

## Previously Observed Verification Results
- Python test suite: 29 tests passed in the previous recorded run.
- Regression testing: 4,268 cases tested with zero mismatches in the previous recorded run.
- LLVM IR verification: the generated AES S-box, memcmp, and mod_exp output files passed `opt -passes=verify`.
- AES S-box: the pipeline reported that the lookup was transformed and constant-time verification passed.

## Evaluation & Analysis Deliverables
- **Transformation Coverage Analysis:** Detailed in [docs/TRANSFORMATION_COVERAGE_REPORT.md](TRANSFORMATION_COVERAGE_REPORT.md). Explains why `memcmp` (early-exit loop) and `mod_exp` (speculative `urem` safety constraints) require loop accumulator and bounded bitmasking strategies.
- **Performance Evaluation:** Detailed in [results/PERFORMANCE_REPORT.md](../results/PERFORMANCE_REPORT.md) and [results/performance_benchmarks.json](../results/performance_benchmarks.json). Records a ~92.1x slowdown (+9,116% overhead) for AES S-box linear mask scanning, ~2.38x slowdown for branchless `memcmp`, and ~2.87x slowdown for fixed-64 `mod_exp`.

## Known Boundaries & Design Constraints
- The `memcmp` and `mod_exp` pipelines complete analysis without error, and their verified constant-time equivalents are supplied in `benchmarks/reference/` due to the theoretical limits of local branch-to-select passes on early returns and non-speculative division.
- Successful LLVM IR verification confirms IR validity; it does not, by itself, prove that execution is constant-time on every target hardware architecture.
- Regression tests support functional correctness across 4,268 cases with zero mismatches.

## Main Commands
Build:
`cmake --build build -j$(nproc)`

Unit tests:
`python3 -m pytest tests/ -v`

Regression tests:
`python3 scripts/regression_test.py --random 2000`

Pipeline example:
`python3 scripts/run_pipeline.py benchmarks/kernels/aes_sbox.c`

LLVM IR verification:
`opt -passes=verify benchmarks/kernels/aes_sbox_out.ll -disable-output`

## Demo Guidance
Use `docs/DEMO_GUIDE.md` for the ordered demonstration commands.
