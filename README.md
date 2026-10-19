<<<<<<< Updated upstream
# Constant-Time Security Transformation Pass

Integrated team project combining the submitted Member 1, Member 2, and Member 3 work.

## Included
- Member 1: SecrecyLabeller and project benchmark/config files
- Member 2: ViolationDetector and detector tests
- Member 3: fixed TaintEngine, memory-content taint tracking, pipeline, and taint-engine test
- Transformer/pass files from the submitted project are included as provided

## Build
Requires LLVM with a discoverable LLVMConfig.cmake.

```bash
mkdir build
cd build
cmake ..
make
```
=======
# Constant-Time Analysis LLVM Pass

A course project implementing a conservative LLVM-IR taint analysis and a prototype constant-time transformer.

## Build

Requires a matching LLVM/Clang toolchain and CMake 3.20+.

```bash
cmake -S . -B build -DLLVM_DIR=/path/to/lib/cmake/llvm
cmake --build build
ctest --test-dir build --output-on-failure
```

Use the same LLVM installation for `clang`, `opt`, and CMake. On Windows, the plugin suffix may be `.dll`; on Linux it is typically `.so`.

## Run a benchmark kernel

From the repository root:

```bash
python scripts/run_pipeline.py benchmarks/kernels/memcmp.c
```

The script emits `<kernel>.ll`, `<kernel>_mem2reg.ll`, and `<kernel>_out.ll`. It uses `mem2reg` before the custom pass so stack slots and parameter origins are represented in SSA form.

The Member 3 standalone analyser accepts an LLVM IR file and a JSON config:

```bash
build/member3_pipeline input.ll benchmarks/configs/memcmp.json
```

## Components

- `SecrecyLabeller`: maps config parameter names to initial labels.
- `TaintEngine`: fixed-point data-flow propagation, field-insensitive memory taint, and conservative control-dependence taint.
- `ViolationDetector`: reports secret-dependent branches and secret-dependent memory addresses.
- `ConstantTimeTransformer`: prototype rewrites for supported branch/table-lookup patterns.
- `tests/`: C++ LLVM-backed regression case and Python contract checks.
- `docs/member3-algorithm.md`: transfer functions, convergence, conservative assumptions, and limitations.

## Important limitations

This is a prototype, not a verified constant-time compiler. The transformation supports only restricted IR shapes. A secret-dependent loop condition remains a timing leak and is out of scope for the select-based transformation. Always rerun analysis on transformed IR before interpreting a zero-leak result.
>>>>>>> Stashed changes
