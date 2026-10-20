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

## Known Limitations
- The memcmp and mod_exp pipelines completed, but the transformer reported that it made no changes to those functions.
- Successful LLVM IR verification confirms IR validity; it does not, by itself, prove that execution is constant-time on every target.
- Regression tests support functional correctness for the tested cases but do not constitute a universal security proof.
- Performance claims must be based on repeatable benchmark measurements.

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
