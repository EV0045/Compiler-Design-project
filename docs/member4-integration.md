# Member 4 integration: mask-based lookup transformation

## Integrated changes

The AES lookup transformation now uses a full-width mask for each candidate table
entry instead of emitting a `select` for each index comparison:

1. Compare the secret index against a public constant index.
2. Sign-extend the `i1` comparison result to the integer element width (`0` or all
   bits set).
3. AND the mask with the candidate table element.
4. OR the masked candidate into the accumulated result.

The transformation explicitly rejects non-integer table elements. This is a
restricted constant-time lowering for integer lookup tables, not a general
transformation for arbitrary LLVM types.

## Member 4 supplied benchmark

Source: `results/aes_benchmark.txt`.

- Compiler: LLVM/Clang 21.1.8
- Optimization: `-O2`
- Inputs per implementation: 5,000,000
- Original CPU time: 0.006577 s
- Transformed CPU time: 0.606140 s
- Reported overhead: 9116.06%; reported slowdown: approximately 92.1x
- Reported correctness: all 256 AES inputs matched
- Reported IR verification: passed

These are the benchmark results supplied with Member 4's archive; they have not
been independently rerun in this integration environment. The substantial
slowdown should be discussed in the report as a security/performance trade-off.
