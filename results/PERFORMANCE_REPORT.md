# Performance Measurement & Benchmark Analysis Report

**Project:** Constant-Time Security Transformation Pass  
**Author:** Compiler Design Team (Member 4: Vignesh Ekambaram, Member 2: Thurya Shrikaa L D)  
**Date:** October 20, 2026  
**Compiler:** LLVM / Clang 19 / 21 (`-O2` optimization)  

---

## 1. Overview

Constant-time transformations defend against side-channel attacks by eliminating data-dependent branch execution times and cache-dependent memory access latencies. This security hardening introduces runtime overhead because:
1. Secret-dependent early returns are converted to full scans.
2. Direct memory lookups are converted to exhaustive table scans.
3. Secret-dependent operations are executed unconditionally with masking.

This report documents the performance measurements, slowdown percentages, and architectural analysis for the target kernels.

---

## 2. Benchmark Results Summary

| Benchmark Kernel | Baseline Implementation | Constant-Time Implementation | Workload / Inputs | Baseline Time | Constant-Time Time | Overhead (%) | Slowdown Factor | Functional Correctness |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AES S-box** | GEP Cache Lookup (`aes_sbox.c`) | **Pass-Transformed** Masked Scan (`aes_sbox_out.ll`) | 5,000,000 lookups | **0.006577 s** | **0.606140 s** | **+9,116.06%** | **~92.1x** | 256 / 256 matched (100%) |
| **`memcmp`** | Naive Early-Exit Loop (`memcmp.c`) | Hand-Written Branchless Scan (`memcmp_ct.c`) | 2,000 pairs ($N=64$) | **0.000120 s** | **0.000285 s** | **+137.50%** | **~2.38x** | 2,005 cases matched (100%) |
| **`mod_exp`** | Naive Montgomery Ladder (`mod_exp.c`) | Hand-Written Fixed-64 Scan (`mod_exp_ct.c`) | 2,000 exponentiations (64-bit) | **0.000840 s** | **0.002410 s** | **+186.90%** | **~2.87x** | 2,007 cases matched (100%) |

---

## 3. Deep-Dive Analysis by Kernel

### 3.1 AES S-box Lookup (Pass-Transformed)
* **Measurement Details:**
  * Baseline: `0.006577 seconds` (5,000,000 lookups)
  * Pass-Transformed: `0.606140 seconds` (5,000,000 lookups)
  * **Measured Slowdown:** $\approx 92.1\times$ ($+9,116\%$ overhead)
* **Architectural Explanation:**
  * Baseline execution: Performs a single pointer calculation and a single L1 cache read:
    $$\text{Cycles} \approx 4\text{ to }5\text{ cycles per lookup}$$
  * Transformed execution: The compiler pass rewrote the table lookup into 256 linear iterations. In each iteration, it performs:
    1. Equality comparison (`icmp eq`)
    2. Sign extension to full element width (`sext`)
    3. Bitwise AND with constant table entry (`and`)
    4. Bitwise OR into cumulative accumulator (`or`)
  * Total instructions executed per lookup: $256 \times 4 = 1,024$ instructions.
  * Achieving $\approx 92\times$ slowdown for $256\times$ more operations indicates good instruction-level parallelism (ILP) and vectorization pipelining by LLVM's backend.

### 3.2 Constant-Time `memcmp`
* **Measurement Details:**
  * Baseline: `0.000120 seconds`
  * Constant-Time: `0.000285 seconds`
  * **Measured Slowdown:** $\approx 2.38\times$ ($+137.5\%$ overhead)
* **Architectural Explanation:**
  * When buffers differ at early byte positions, the baseline exits on iteration 1.
  * The constant-time version always processes all $N$ bytes, issuing $N$ XOR and OR operations.
  * The $\approx 2.4\times$ overhead represents the amortized cost across random byte buffers.

### 3.3 Constant-Time Modular Exponentiation (`mod_exp`)
* **Measurement Details:**
  * Baseline: `0.000840 seconds`
  * Constant-Time: `0.002410 seconds`
  * **Measured Slowdown:** $\approx 2.87\times$ ($+186.9\%$ overhead)
* **Architectural Explanation:**
  * The baseline executes modular multiplication only when an exponent bit is 1 (50% of the time on average) and terminates as soon as remaining bits are zero.
  * The constant-time implementation always executes 64 complete multiplication and reduction cycles, followed by bitwise multiplexing.
  * This $\approx 2.9\times$ factor matches theoretical expectations ($2\times$ from unconditional multiply $+ 1.4\times$ from fixed 64-bit normalization).

---

## 4. Verification and Security Impact

1. **LLVM IR Verification:** The transformed IR passes `opt -passes=verify` with zero structural defects.
2. **Regression Testing:** All 4,268 automated test cases produced zero output discrepancies between baseline and constant-time implementations.
3. **Security Assurance:** The cache-timing channel in AES and the execution-time oracles in memcmp and mod_exp are eliminated at the cost of bounded, predictable performance overhead.
