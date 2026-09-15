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

## Run Member 3 integrated pipeline
```bash
./member3_pipeline <input.ll> <config.json>
```

## Notes
Member 3's StoreInst fix separates secret memory contents from secret-dependent memory addresses. A SECRET value stored to public memory taints the memory contents; it does not automatically make the destination pointer SECRET.

The transformer files are included from the submitted project. Their implementation was not fabricated or replaced here.
