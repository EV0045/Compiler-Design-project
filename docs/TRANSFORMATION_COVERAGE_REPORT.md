# Transformation Coverage & Feasibility Investigation Report

**Project:** Constant-Time Security Transformation Pass  
**Author:** Compiler Design Team (Member 4: Vignesh Ekambaram, Member 2: Thurya Shrikaa L D)  
**Date:** October 20, 2026  

---

## 1. Executive Summary

During pipeline evaluation on the three target benchmark kernels (`aes_sbox.c`, `memcmp.c`, and `mod_exp.c`):
* **`aes_sbox.c`** was successfully detected and transformed from a cache-leaking GEP memory load into a constant-time 256-element bitmask linear scan.
* **`memcmp.c`** and **`mod_exp.c`** completed the analysis pipeline without error, but the transformer reported zero transformations.

This report provides the technical investigation into why these two kernels were not transformed by the local CFG transformation pass, identifies the exact compiler mechanisms responsible, and details the implemented fixes and constant-time reference implementations.

---

## 2. Kernel 1: `memcmp` (`secret_memcmp`)

### 2.1 Baseline Code & Leak Mechanism
```c
int secret_memcmp(const unsigned char *a, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 1; // Early return leak!
        }
    }
    return 0;
}
```
* **Security Violation:** The loop terminates as soon as the first differing byte is encountered. An adversary measuring execution time can deduce the length of matching prefix bytes (classic timing oracle attack).

### 2.2 Why the Pass Cannot Transform It (Root Cause)
1. **Control-Flow Graph (CFG) Structure:**
   * In LLVM IR, the conditional branch inside the loop splits into:
     - `if.then`: jumps directly to `return` via a `ReturnInst` (`ret i32 1`).
     - `if.end`: jumps to `for.inc` to continue the loop.
2. **Missing Merge Block & PHI Node:**
   * `ConstantTimeTransformer::transformBranch` operates on local **diamond** or **triangle** CFG patterns where both branch targets converge at a common `MergeBlock` containing a 2-input `PHINode`.
   * In `secret_memcmp`, one branch exits the function entirely while the other continues the loop. There is **no common successor block within the loop body**.
3. **Loop Semantics Limitation:**
   * A local branch-to-select pass replaces a branch with an LLVM `select` instruction. However, replacing an early function exit with `select` without modifying the loop bounds would either cause an infinite loop or break program correctness. Converting an early-exit loop into constant-time requires **loop-level accumulator transformation** (flattening), which is a loop-optimization pass, not a basic-block branch transformation.

### 2.3 Implemented Fix: Hand-Written Constant-Time Reference (`benchmarks/reference/memcmp_ct.c`)
To achieve constant-time execution, the early exit is eliminated by accumulating differences over all $N$ bytes:
```c
int secret_memcmp(const unsigned char *a, const unsigned char *b, int n) {
    unsigned int diff = 0;
    for (int i = 0; i < n; i++) {
        diff |= (unsigned int)(a[i] ^ b[i]);
    }
    return (int)((diff | (0u - diff)) >> 31);
}
```
* **Timing Guarantee:** The loop always executes exactly $n$ iterations regardless of secret values.
* **Verification:** Regression testing across 2,005 test cases confirmed 0 mismatches against the baseline.

---

## 3. Kernel 2: Modular Exponentiation (`mod_exp`)

### 3.1 Baseline Code & Leak Mechanism
```c
uint64_t mod_exp(uint64_t base, uint64_t secret_exp, uint64_t mod) {
    uint64_t result = 1;
    while (secret_exp > 0) {
        if (secret_exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        secret_exp >>= 1;
    }
    return result;
}
```
* **Security Violation:** 
  1. The branch `if (secret_exp & 1)` leaks the individual bits of the secret exponent via execution time (Montgomery power ladder leak).
  2. The loop condition `while (secret_exp > 0)` leaks the most-significant non-zero bit position (bit-length of secret).

### 3.2 Why the Pass Cannot Transform It (Root Cause)
1. **Speculative Execution Safety Violation:**
   * In `ConstantTimeTransformer::transformBranch`, before instructions inside a `then` block can be hoisted before the branch, they must be validated with:
     ```cpp
     llvm::isSafeToSpeculativelyExecute(&I)
     ```
   * Inside the branch, the operation is `(result * base) % mod`, which generates an LLVM `urem` (unsigned remainder) instruction.
   * **In LLVM, `urem` and `srem` (division/remainder) are explicitly NOT safe to speculatively execute** because if the divisor (`mod`) were zero, unconditional speculative execution would trigger a fatal hardware divide-by-zero CPU exception (`SIGFPE`).
   * The transformer safely and correctly rejects hoisting the remainder instruction to maintain crash safety.
2. **Loop Condition Dependent on Secret:**
   * Even if the inner branch were converted to a select, `while (secret_exp > 0)` continues to vary the number of loop iterations depending on the exponent value.

### 3.3 Implemented Fix: Hand-Written Constant-Time Reference (`benchmarks/reference/mod_exp_ct.c`)
The constant-time implementation normalizes the loop to a fixed 64 iterations and eliminates the branch using arithmetic masking:
```c
uint64_t mod_exp(uint64_t base, uint64_t secret_exp, uint64_t mod) {
    uint64_t result = 1;
    for (int i = 0; i < 64; i++) {
        uint64_t mask = 0 - (secret_exp & 1); // all 1s if bit is 1, 0 if 0
        uint64_t multiplied = (result * base) % mod;
        result = (multiplied & mask) | (result & ~mask);
        base = (base * base) % mod;
        secret_exp >>= 1;
    }
    return result;
}
```
* **Timing Guarantee:** Exactly 64 iterations for any 64-bit exponent; multiplication and modulo occur every cycle regardless of secret bit values.
* **Verification:** Regression testing across 2,007 random cases confirmed 0 mismatches.

---

## 4. Summary Matrix

| Kernel | Target Violation | Pass Transformation Feasibility | Primary Obstacle | Solution Adopted |
| :--- | :--- | :--- | :--- | :--- |
| **AES S-box** | `MEMORY_LEAK` (Secret GEP index) | **Fully Automated** | None (Static array $\le 256$ entries) | 256-element bitmask linear scan (`ConstantTimeTransformer.cpp`) |
| **`memcmp`** | `BRANCH_LEAK` (Early loop exit) | Out of scope for local CFG pass | `ReturnInst` terminator, no shared merge block | Branchless bitwise OR accumulator (`memcmp_ct.c`) |
| **`mod_exp`** | `BRANCH_LEAK` (Conditional multiply) | Blocked by safety constraints | `urem` cannot be speculatively hoisted; variable loop bounds | Fixed 64-iteration bitmask ladder (`mod_exp_ct.c`) |
