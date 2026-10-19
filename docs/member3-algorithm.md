# Member 3 — Taint analysis algorithm

## Analysis domain

Each SSA value is labelled `PUBLIC` or `SECRET`. Labels are monotone: once a value becomes secret, it remains secret during one analysis. LLVM constants are always public. Pointer-address secrecy is separate from pointee-content secrecy: a secret pointer parameter seeds the field-insensitive memory map for the pointed-to object, while the pointer value itself remains public.

## Transfer functions

| IR instruction | Result / memory rule |
|---|---|
| Integer/floating binary operation | Secret if any operand is secret |
| Compare | Secret if either compared operand is secret |
| Cast | Secret if source is secret |
| `select` | Secret if condition or either candidate is secret |
| `phi` | Secret if any incoming value is secret; additionally secret under secret control dependence |
| GEP | Secret only when an index is secret; a secret base pointer alone does not taint the address |
| Load | Secret if its address is secret or its field-insensitive pointee memory is secret |
| Store | Secret stored value marks the destination's field-insensitive memory secret |
| Call | Result is secret if a scalar argument or pointer-to-secret-memory argument is secret; for unknown calls, pointer arguments are conservatively treated as output memory when an input is secret |
| Constants | Public |

Memory is field-insensitive: GEPs and casts are reduced to a common base key. This is conservative and can overtaint distinct fields/array elements.

## CFG and convergence

Blocks are visited in reverse post-order, with unreachable blocks appended. The engine repeats transfer functions and implicit-flow propagation until a full pass makes no changes. Since the label lattice has only two elements and updates only move `PUBLIC` to `SECRET`, termination is guaranteed: each tracked value and memory key can change at most once. `getIterationCount()` exposes the number of fixed-point rounds for experiments.

For each conditional branch whose condition is secret, the post-dominator tree supplies its immediate post-dominator as the join. A reachability walk marks memory written in the controlled region secret, stopping at the join; phis in the join are marked secret. This intentionally conservative treatment may taint more values than a path-sensitive analysis.

## Limitations

- This is a static taint approximation, not a proof of constant-time behavior.
- External-call side effects are conservatively approximated.
- The transformer only handles selected branch shapes and constant global lookup tables.
- A secret-dependent loop such as `while (secret_exp > 0)` leaks through iteration count. A select-based transformation cannot remove that timing leak; the detector can report it, but loop restructuring is out of scope.
- Re-run labelling and taint analysis after any IR transformation before calling `verifyZeroLeaks`. Never reuse a taint map after instructions/phis have been erased, because it can contain stale LLVM pointers.

## Suggested experiment report

Record the LLVM version, kernel/config, fixed-point iteration count, each violation type and source location, and whether transformation succeeded. Do not claim zero leaks merely because a transformation ran: re-analyse the transformed IR and verify it.
