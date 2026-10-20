# Static & Dynamic Verification Report (Week 3 Deliverable)

**Project:** Constant-Time Security Transformation Pass  
**Module Owner:** Member 2 (Thurya Shrikaa L D) — Violation Detector & Static Verifier  
**Date:** October 20, 2026  
**Tools:** LLVM C++ Pass Infrastructure, Python Unit & Integration Test Suite, `ctgrind` (Valgrind Memcheck)  

---

## 1. Executive Summary

Member 2 is responsible for:
1. **Instruction Inspection:** Identifying candidate instructions susceptible to timing leaks (conditional branches, loads, stores, address calculations/GEPs).
2. **Violation Detection:** Mapping propagated taint results from Member 3 (`TaintEngine`) to pinpoint exact violation sites (`BRANCH_LEAK` and `MEMORY_LEAK`).
3. **Post-Transformation Static Re-Verification:** Scanning output LLVM IR after Member 4's transformation pass to confirm that zero timing violations remain.
4. **Dynamic Taint Verification:** Setting up automated runtime verification using Valgrind/`ctgrind` to ensure machine code execution is strictly independent of secret data.

This report summarizes the verification results across the target cryptographic kernels before and after constant-time transformation.

---

## 2. Verification Architecture & Contract

### 2.1 Shared Data Contract
```text
TaintEngine (M3) ---> PropagatedTaintMap (std::unordered_map<const Value*, TaintLabel>)
                           |
                           v
ViolationDetector (M2) ---> detectViolations(Function/Module) ---> std::vector<ViolationSite>
                           |
                           v
Post-Transform Verifier ---> verifyZeroLeaks(Module, remainingLeaks) ---> bool (PASS / FAIL)
```

### 2.2 Leak Classification
* **`BRANCH_LEAK` (Control-Flow Timing Side Channel):** A conditional branch (`BranchInst::isConditional()`) whose predicate depends on a `SECRET` value. Execution latency varies based on which branch path is taken.
* **`MEMORY_LEAK` (Cache-Timing Side Channel):** A memory load (`LoadInst`), store (`StoreInst`), or pointer calculation (`GetElementPtrInst`) where the target address or indexing offset depends on a `SECRET` value. Memory access latencies vary due to CPU cache hits and misses (e.g., CacheBleed, Spectre-style attacks).

---

## 3. Pre-Transformation Detection Results

The detector scanned the baseline cryptographic kernels with the following initial secrecy annotations:

| Benchmark Kernel | Function Analyzed | Secret Parameter(s) | Detected Violation Sites | Leak Type | Diagnostic Description |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **AES S-box** | `aes_sbox` | `input` (key/plaintext byte) | **1** | `MEMORY_LEAK` | Secret-dependent index in GetElementPtr (`sbox[input]`) |
| **`memcmp`** | `secret_memcmp` | `a`, `b` (buffer contents) | **1** | `BRANCH_LEAK` | Conditional branch depends on secret buffer difference (`a[i] != b[i]`) |
| **`mod_exp`** | `mod_exp` | `secret_exp` (exponent) | **1** | `BRANCH_LEAK` | Conditional branch depends on exponent bit (`secret_exp & 1`) |

*Result:* Pre-transformation verification correctly flagged **all 3 seeded side channels** with zero false negatives.

---

## 4. Post-Transformation Static Verification

Following transformation, the detector executed `verifyZeroLeaks(Module&, ...)` and `verifyZeroLeaks(Function&, ...)` on the output IR:

| Kernel | Transformation Method | Post-Transform Violations | Remaining Leaks | Verification Status |
| :--- | :--- | :---: | :---: | :---: |
| **AES S-box** | Pass-Transformed (256-bitmask scan) | **0** | None | ✅ **PASS (Zero Leaks)** |
| **`memcmp`** | Constant-Time Reference (accumulator) | **0** | None | ✅ **PASS (Zero Leaks)** |
| **`mod_exp`** | Constant-Time Reference (fixed 64-bit) | **0** | None | ✅ **PASS (Zero Leaks)** |

### 4.1 Automated Module-Level Verification
The module-level API implemented in `ViolationDetector.cpp`:
```cpp
bool ViolationDetector::verifyZeroLeaks(llvm::Module &M,
                                       const TaintMap &taintMap,
                                       std::vector<ViolationSite> &remainingLeaks);
```
Iterates through all non-declaration functions in the module:
1. Re-analyzes instructions against the post-transformation taint state.
2. Accumulates any residual `BRANCH_LEAK` or `MEMORY_LEAK` sites.
3. Returns `true` only if `remainingLeaks.empty()`.

When integrated in `src/PassRegistration.cpp`, the pass logs:
```text
CT verification passed for function: aes_sbox
```

---

## 5. Dynamic Verification via `ctgrind` (`scripts/verify_ctgrind.sh`)

To complement static LLVM IR verification with dynamic execution guarantees, Member 2 created `scripts/verify_ctgrind.sh`:

### 5.1 Mechanism
1. Utilizes Valgrind's Memcheck engine with client requests (`VALGRIND_MAKE_MEM_UNDEFINED`).
2. Marks secret buffers/keys as "undefined" memory.
3. If any CPU branch instruction or memory addressing mode accesses undefined memory, Valgrind generates a fatal diagnostic:
   * `"Conditional jump or move depends on uninitialised value(s)"`
   * `"Use of uninitialised value of size N"`
4. In constant-time code, all operations on secret data are strictly bitwise arithmetic (`and`, `or`, `xor`, `select`), which Valgrind propagates without triggering timing errors.

### 5.2 Verification Modes
* `--pre`: Validates that the baseline kernel correctly triggers ctgrind alerts (demonstrating attack viability).
* `--post`: Validates that the transformed binary executes with **0 timing warnings**.
* `--diff`: Differential mode comparing leak counts between naive and hardened binaries.

---

## 6. Test Suite Coverage (`tests/test_detector.py`)

The automated Python test suite validates Member 2's components across 22 comprehensive test cases:

1. **`TestViolationDetector` (Week 1):** 7 tests covering candidate isolation, conditional branch leaks, memory load/store leaks, GEP index leaks, and static zero-leak verification.
2. **`TestDetectorTaintEngineIntegration` (Week 2):** 7 tests covering multi-block propagation, PHI-node taint propagation, crypto kernels, and data contract compatibility with Member 3.
3. **`TestWeek3PostTransformVerification` (Week 3):** 8 tests (W3-1 through W3-8) covering:
   * Clean single functions (PASS)
   * Partial transformations with residual branch leaks (FAIL)
   * Partial transformations with residual GEP leaks (FAIL)
   * Multiple residual leaks reporting (FAIL)
   * Module-level all-clean pass (PASS)
   * Module-level dirty function detection (FAIL)
   * AES S-box post-transformation verification (PASS)
   * memcmp post-transformation branch elimination verification (PASS)

*Overall Test Status:* **22 / 22 Passed (100% pass rate).**
