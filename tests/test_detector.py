#!/usr/bin/env python3
"""
Unit tests for Member 2 (Thurya) - Violation Detector & Static Verifier.

Tests cover:
1. Week 1 Instruction Inspector:
   - Isolating target candidate instructions (`br`, `load`, `store`, `gep`) within Basic Blocks.
2. Violation Detection:
   - Tainted conditional branch detection (`BRANCH_LEAK`).
   - Unconditional and public branch non-violations (safe).
   - Secret-dependent memory loads and stores (`MEMORY_LEAK`).
   - Secret-dependent GetElementPtr array indexing (`MEMORY_LEAK`).
3. Static Verifier:
   - Zero-leak post-transformation verification check.
4. Realistic Crypto Kernel Scenarios:
   - `memcmp` early exit timing leak.
   - `aes_sbox` secret-indexed table lookup leak.
   - `mod_exp` secret exponent-dependent branching leak.
"""

import unittest
from enum import Enum
from typing import List, Dict, Optional, Tuple


class TaintLabel(Enum):
    PUBLIC = 0
    SECRET = 1


class ViolationType(Enum):
    BRANCH_LEAK = "BRANCH_LEAK"
    MEMORY_LEAK = "MEMORY_LEAK"


class MockValue:
    """Mock representation of llvm::Value."""
    def __init__(self, name: str, is_constant: bool = False):
        self.name = name
        self.is_constant = is_constant

    def __repr__(self):
        return f"%{self.name}" if not self.is_constant else f"const({self.name})"


class MockInstruction(MockValue):
    """Base mock representation of llvm::Instruction."""
    def __init__(self, name: str, opcode: str, source_loc: str = ""):
        super().__init__(name)
        self.opcode = opcode
        self.source_loc = source_loc


class MockBranchInst(MockInstruction):
    """Mock representation of llvm::BranchInst."""
    def __init__(self, name: str, condition: Optional[MockValue] = None, source_loc: str = ""):
        super().__init__(name, "br", source_loc)
        self.condition = condition

    def is_conditional(self) -> bool:
        return self.condition is not None


class MockLoadInst(MockInstruction):
    """Mock representation of llvm::LoadInst."""
    def __init__(self, name: str, ptr_operand: MockValue, source_loc: str = ""):
        super().__init__(name, "load", source_loc)
        self.ptr_operand = ptr_operand


class MockStoreInst(MockInstruction):
    """Mock representation of llvm::StoreInst."""
    def __init__(self, name: str, val_operand: MockValue, ptr_operand: MockValue, source_loc: str = ""):
        super().__init__(name, "store", source_loc)
        self.val_operand = val_operand
        self.ptr_operand = ptr_operand


class MockGetElementPtrInst(MockInstruction):
    """Mock representation of llvm::GetElementPtrInst."""
    def __init__(self, name: str, base_ptr: MockValue, indices: List[MockValue], source_loc: str = ""):
        super().__init__(name, "getelementptr", source_loc)
        self.base_ptr = base_ptr
        self.indices = indices


class MockBasicBlock:
    """Mock representation of llvm::BasicBlock."""
    def __init__(self, name: str):
        self.name = name
        self.instructions: List[MockInstruction] = []

    def add_instruction(self, inst: MockInstruction):
        self.instructions.append(inst)


class MockFunction:
    """Mock representation of llvm::Function."""
    def __init__(self, name: str):
        self.name = name
        self.basic_blocks: List[MockBasicBlock] = []

    def add_basic_block(self, bb: MockBasicBlock):
        self.basic_blocks.append(bb)


class ViolationSite:
    """Represents a detected violation site matching C++ ct_pass::ViolationSite."""
    def __init__(self, instruction: MockInstruction, v_type: ViolationType, 
                 leaking_operand: MockValue, description: str, source_loc: str = ""):
        self.instruction = instruction
        self.type = v_type
        self.leaking_operand = leaking_operand
        self.description = description
        self.source_loc = source_loc

    def __repr__(self):
        return f"<ViolationSite {self.type.value} inst={self.instruction.name} operand={self.leaking_operand.name}>"


class ViolationDetector:
    """
    Python mirror of C++ ct_pass::ViolationDetector logic.
    Executes identical verification algorithms for testing.
    """
    def is_secret(self, val: Optional[MockValue], taint_map: Dict[str, TaintLabel]) -> bool:
        if not val or val.is_constant:
            return False
        return taint_map.get(val.name, TaintLabel.PUBLIC) == TaintLabel.SECRET

    def isolate_candidate_instructions(self, func: MockFunction) -> List[MockInstruction]:
        """Week 1 Deliverable: Isolate all candidate instructions in basic blocks."""
        candidates = []
        for bb in func.basic_blocks:
            for inst in bb.instructions:
                if isinstance(inst, MockBranchInst) and inst.is_conditional():
                    candidates.append(inst)
                elif isinstance(inst, (MockLoadInst, MockStoreInst, MockGetElementPtrInst)):
                    candidates.append(inst)
        return candidates

    def inspect_branch(self, bi: MockBranchInst, taint_map: Dict[str, TaintLabel]) -> Optional[ViolationSite]:
        if not bi.is_conditional():
            return None
        if self.is_secret(bi.condition, taint_map):
            return ViolationSite(
                instruction=bi,
                v_type=ViolationType.BRANCH_LEAK,
                leaking_operand=bi.condition,
                description="Conditional branch depends on secret data (control-flow timing side channel)",
                source_loc=bi.source_loc
            )
        return None

    def inspect_memory(self, inst: MockInstruction, taint_map: Dict[str, TaintLabel]) -> Optional[ViolationSite]:
        if isinstance(inst, MockLoadInst):
            if self.is_secret(inst.ptr_operand, taint_map):
                return ViolationSite(
                    instruction=inst,
                    v_type=ViolationType.MEMORY_LEAK,
                    leaking_operand=inst.ptr_operand,
                    description="Memory load from secret-dependent address (cache-timing side channel)",
                    source_loc=inst.source_loc
                )
        elif isinstance(inst, MockStoreInst):
            if self.is_secret(inst.ptr_operand, taint_map):
                return ViolationSite(
                    instruction=inst,
                    v_type=ViolationType.MEMORY_LEAK,
                    leaking_operand=inst.ptr_operand,
                    description="Memory store to secret-dependent address (cache-timing side channel)",
                    source_loc=inst.source_loc
                )
        return None

    def inspect_gep(self, gep: MockGetElementPtrInst, taint_map: Dict[str, TaintLabel]) -> Optional[ViolationSite]:
        if self.is_secret(gep.base_ptr, taint_map):
            return ViolationSite(
                instruction=gep,
                v_type=ViolationType.MEMORY_LEAK,
                leaking_operand=gep.base_ptr,
                description="Pointer arithmetic on secret base address (cache-timing side channel)",
                source_loc=gep.source_loc
            )
        for idx in gep.indices:
            if self.is_secret(idx, taint_map):
                return ViolationSite(
                    instruction=gep,
                    v_type=ViolationType.MEMORY_LEAK,
                    leaking_operand=idx,
                    description="Secret-dependent index calculation in GetElementPtr (cache lookup side channel)",
                    source_loc=gep.source_loc
                )
        return None

    def detect_violations(self, func: MockFunction, taint_map: Dict[str, TaintLabel]) -> List[ViolationSite]:
        violations = []
        for bb in func.basic_blocks:
            for inst in bb.instructions:
                if isinstance(inst, MockBranchInst):
                    v = self.inspect_branch(inst, taint_map)
                    if v:
                        violations.append(v)
                elif isinstance(inst, MockGetElementPtrInst):
                    v = self.inspect_gep(inst, taint_map)
                    if v:
                        violations.append(v)
                elif isinstance(inst, (MockLoadInst, MockStoreInst)):
                    v = self.inspect_memory(inst, taint_map)
                    if v:
                        violations.append(v)
        return violations

    def verify_zero_leaks(self, func: MockFunction, taint_map: Dict[str, TaintLabel]) -> Tuple[bool, List[ViolationSite]]:
        violations = self.detect_violations(func, taint_map)
        return (len(violations) == 0, violations)


class TestViolationDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ViolationDetector()

    def test_week1_isolate_candidate_instructions(self):
        """Verify that Week 1 inspector successfully isolates br, load, store, GEP."""
        fn = MockFunction("kernel")
        bb1 = MockBasicBlock("entry")

        # Instruction mix: conditional br, unconditional br, load, store, gep, other (add)
        cond = MockValue("cond")
        addr = MockValue("addr")
        val = MockValue("val")
        idx = MockValue("idx")

        inst_br_cond = MockBranchInst("br_cond", condition=cond)
        inst_br_uncond = MockBranchInst("br_uncond", condition=None)
        inst_load = MockLoadInst("ld", ptr_operand=addr)
        inst_store = MockStoreInst("st", val_operand=val, ptr_operand=addr)
        inst_gep = MockGetElementPtrInst("gep", base_ptr=addr, indices=[idx])
        inst_other = MockInstruction("add_inst", opcode="add")

        bb1.add_instruction(inst_other)
        bb1.add_instruction(inst_br_cond)
        bb1.add_instruction(inst_br_uncond)
        bb1.add_instruction(inst_load)
        bb1.add_instruction(inst_store)
        bb1.add_instruction(inst_gep)
        fn.add_basic_block(bb1)

        candidates = self.detector.isolate_candidate_instructions(fn)
        candidate_names = [c.name for c in candidates]

        # Should isolate conditional branch, load, store, gep
        self.assertIn("br_cond", candidate_names)
        self.assertIn("ld", candidate_names)
        self.assertIn("st", candidate_names)
        self.assertIn("gep", candidate_names)

        # Should exclude unconditional branch and regular arithmetic
        self.assertNotIn("br_uncond", candidate_names)
        self.assertNotIn("add_inst", candidate_names)
        self.assertEqual(len(candidates), 4)

    def test_branch_leak_detection(self):
        """Verify secret condition flags BRANCH_LEAK, while public condition does not."""
        fn = MockFunction("branch_test")
        bb = MockBasicBlock("entry")

        secret_cond = MockValue("secret_cond")
        public_cond = MockValue("public_cond")

        bi_leak = MockBranchInst("bi_leak", condition=secret_cond, source_loc="test.c:12:5")
        bi_safe = MockBranchInst("bi_safe", condition=public_cond, source_loc="test.c:15:5")

        bb.add_instruction(bi_leak)
        bb.add_instruction(bi_safe)
        fn.add_basic_block(bb)

        taint_map = {
            "secret_cond": TaintLabel.SECRET,
            "public_cond": TaintLabel.PUBLIC
        }

        violations = self.detector.detect_violations(fn, taint_map)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].instruction.name, "bi_leak")
        self.assertEqual(violations[0].leaking_operand.name, "secret_cond")
        self.assertEqual(violations[0].source_loc, "test.c:12:5")

    def test_memory_load_store_leak_detection(self):
        """Verify secret pointer flags MEMORY_LEAK, while public pointer does not."""
        fn = MockFunction("mem_test")
        bb = MockBasicBlock("entry")

        sec_ptr = MockValue("sec_ptr")
        pub_ptr = MockValue("pub_ptr")
        data = MockValue("data")

        ld_leak = MockLoadInst("ld_leak", ptr_operand=sec_ptr)
        ld_safe = MockLoadInst("ld_safe", ptr_operand=pub_ptr)
        st_leak = MockStoreInst("st_leak", val_operand=data, ptr_operand=sec_ptr)
        st_safe = MockStoreInst("st_safe", val_operand=sec_ptr, ptr_operand=pub_ptr)  # Storing secret data to public ptr is CT-safe

        bb.add_instruction(ld_leak)
        bb.add_instruction(ld_safe)
        bb.add_instruction(st_leak)
        bb.add_instruction(st_safe)
        fn.add_basic_block(bb)

        taint_map = {
            "sec_ptr": TaintLabel.SECRET,
            "pub_ptr": TaintLabel.PUBLIC,
            "data": TaintLabel.PUBLIC
        }

        violations = self.detector.detect_violations(fn, taint_map)
        self.assertEqual(len(violations), 2)
        v_names = [v.instruction.name for v in violations]
        self.assertIn("ld_leak", v_names)
        self.assertIn("st_leak", v_names)
        self.assertNotIn("st_safe", v_names)  # Safe: address is public
        self.assertNotIn("ld_safe", v_names)

    def test_gep_array_lookup_leak(self):
        """Verify secret index in GEP (e.g., table[secret]) flags MEMORY_LEAK."""
        fn = MockFunction("gep_test")
        bb = MockBasicBlock("entry")

        table_base = MockValue("sbox_table")
        secret_idx = MockValue("secret_byte")
        pub_idx = MockValue("pub_idx", is_constant=True)

        gep_leak = MockGetElementPtrInst("gep_leak", base_ptr=table_base, indices=[secret_idx])
        gep_safe = MockGetElementPtrInst("gep_safe", base_ptr=table_base, indices=[pub_idx])

        bb.add_instruction(gep_leak)
        bb.add_instruction(gep_safe)
        fn.add_basic_block(bb)

        taint_map = {
            "sbox_table": TaintLabel.PUBLIC,
            "secret_byte": TaintLabel.SECRET
        }

        violations = self.detector.detect_violations(fn, taint_map)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.MEMORY_LEAK)
        self.assertEqual(violations[0].instruction.name, "gep_leak")
        self.assertEqual(violations[0].leaking_operand.name, "secret_byte")

    def test_static_verifier_zero_leaks(self):
        """Verify post-transformation static verification behavior."""
        fn_clean = MockFunction("transformed_clean")
        bb = MockBasicBlock("entry")
        bb.add_instruction(MockLoadInst("clean_ld", ptr_operand=MockValue("pub_addr")))
        fn_clean.add_basic_block(bb)

        clean_map = {"pub_addr": TaintLabel.PUBLIC}
        ok, leaks = self.detector.verify_zero_leaks(fn_clean, clean_map)
        self.assertTrue(ok)
        self.assertEqual(len(leaks), 0)

    def test_kernel_aes_sbox_scenario(self):
        """Realistic Scenario: AES S-box table lookup with secret key byte."""
        fn = MockFunction("aes_sbox_kernel")
        bb = MockBasicBlock("entry")

        sbox = MockValue("AES_SBOX_TABLE")
        key_byte = MockValue("key_byte")

        gep_inst = MockGetElementPtrInst("sbox_addr", base_ptr=sbox, indices=[key_byte], source_loc="aes_sbox.c:18:14")
        load_inst = MockLoadInst("sub_byte", ptr_operand=MockValue("sbox_addr"), source_loc="aes_sbox.c:18:5")

        bb.add_instruction(gep_inst)
        bb.add_instruction(load_inst)
        fn.add_basic_block(bb)

        taint_map = {
            "AES_SBOX_TABLE": TaintLabel.PUBLIC,
            "key_byte": TaintLabel.SECRET,
            "sbox_addr": TaintLabel.SECRET
        }

        violations = self.detector.detect_violations(fn, taint_map)
        self.assertGreaterEqual(len(violations), 1)
        types = [v.type for v in violations]
        self.assertIn(ViolationType.MEMORY_LEAK, types)

    def test_kernel_memcmp_scenario(self):
        """Realistic Scenario: memcmp early-exit branch on secret byte comparison."""
        fn = MockFunction("memcmp_kernel")
        bb = MockBasicBlock("loop_body")

        diff_cmp = MockValue("diff_cmp")
        branch_exit = MockBranchInst("exit_br", condition=diff_cmp, source_loc="memcmp.c:9:9")
        bb.add_instruction(branch_exit)
        fn.add_basic_block(bb)

        taint_map = {
            "diff_cmp": TaintLabel.SECRET
        }

        violations = self.detector.detect_violations(fn, taint_map)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].instruction.name, "exit_br")


<<<<<<< Updated upstream
if __name__ == "__main__":
    unittest.main(verbosity=2)
=======
class MockTaintEngine:
    """
    Python mirror of ct_pass::TaintEngine.
    Simulates the propagated taint map that Member 3's engine produces
    after running fixed-point analysis over a function's CFG.

    The real TaintEngine propagates taint through:
      - BinaryOperator  (e.g., secret & 1  -> secret)
      - CmpInst         (e.g., icmp secret -> secret)
      - CastInst        (e.g., zext secret -> secret)
      - PHINode         (any incoming SECRET -> result is SECRET)
      - GEP             (secret base or index -> result is SECRET)
      - LoadInst        (secret pointer -> result is SECRET)

    Here we pre-build the propagated map manually to test the
    ViolationDetector's behaviour when given engine output.
    """
    def __init__(self, propagated_map: Dict[str, TaintLabel]):
        self._taint_map = propagated_map

    def get_taint_map(self) -> Dict[str, TaintLabel]:
        return self._taint_map

    def is_secret(self, name: str) -> bool:
        return self._taint_map.get(name, TaintLabel.PUBLIC) == TaintLabel.SECRET


class TestDetectorTaintEngineIntegration(unittest.TestCase):
    """
    Week 2 Integration Tests.

    Each test simulates the full Member 3 → Member 2 pipeline:
      1. TaintEngine produces a PropagatedTaintMap after fixed-point analysis.
      2. ViolationDetector.detect_violations() consumes that map.
      3. We assert the correct ViolationSite list is produced.

    Taint propagation chains are hand-computed to mirror what
    TaintEngine.processInstruction() would produce for each kernel.
    """

    def setUp(self):
        self.detector = ViolationDetector()

    def _make_engine(self, propagated: Dict[str, TaintLabel]) -> MockTaintEngine:
        return MockTaintEngine(propagated)

    # ------------------------------------------------------------------
    # Test 1: Contract compatibility — engine output feeds detector directly
    # ------------------------------------------------------------------
    def test_taintengine_contract_compatibility(self):
        """
        The map returned by TaintEngine.get_taint_map() must be usable
        directly as the taint_map argument to detect_violations().
        No type adaptation should be needed.
        """
        engine = self._make_engine({
            "key":      TaintLabel.SECRET,
            "pub_addr": TaintLabel.PUBLIC,
        })

        fn = MockFunction("compat_check")
        bb = MockBasicBlock("entry")
        secret_val = MockValue("key")
        pub_addr   = MockValue("pub_addr")

        bb.add_instruction(MockLoadInst("ld", ptr_operand=pub_addr))
        fn.add_basic_block(bb)

        # Feed engine map directly — no violations (load from public address)
        violations = self.detector.detect_violations(fn, engine.get_taint_map())
        self.assertEqual(len(violations), 0)

    # ------------------------------------------------------------------
    # Test 2: Propagation chain — param → icmp → br (memcmp pattern)
    # ------------------------------------------------------------------
    def test_propagated_taint_branch_chain(self):
        """
        Simulates TaintEngine propagation:
          %secret_param (SECRET, from labeller)
          %diff   = sub  %a[i], %b[i]    -> SECRET (operand is secret)
          %cmp    = icmp %diff, 0         -> SECRET (operand is secret)
          br %cmp, exit, loop             -> BRANCH_LEAK
        """
        # Propagated map: taint has flowed from param through sub and icmp
        engine = self._make_engine({
            "secret_param": TaintLabel.SECRET,
            "diff":         TaintLabel.SECRET,   # sub result
            "cmp":          TaintLabel.SECRET,   # icmp result
        })

        fn = MockFunction("memcmp_kernel")
        bb = MockBasicBlock("loop_body")

        cmp_val    = MockValue("cmp")
        exit_br    = MockBranchInst("exit_br", condition=cmp_val, source_loc="memcmp.c:9:9")
        bb.add_instruction(exit_br)
        fn.add_basic_block(bb)

        violations = self.detector.detect_violations(fn, engine.get_taint_map())
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].leaking_operand.name, "cmp")
        self.assertEqual(violations[0].source_loc, "memcmp.c:9:9")

    # ------------------------------------------------------------------
    # Test 3: Propagation chain — key_byte → GEP index (AES S-box pattern)
    # ------------------------------------------------------------------
    def test_propagated_taint_gep_index_chain(self):
        """
        Simulates TaintEngine propagation:
          %key_byte  (SECRET, from labeller)
          %idx       = zext %key_byte to i64  -> SECRET (cast propagates taint)
          %sbox_addr = getelementptr sbox, %idx -> MEMORY_LEAK (secret index)
          %sub_byte  = load %sbox_addr          -> MEMORY_LEAK (secret pointer)
        """
        engine = self._make_engine({
            "key_byte":  TaintLabel.SECRET,
            "idx":       TaintLabel.SECRET,   # zext result
            "sbox_addr": TaintLabel.SECRET,   # GEP result
            "AES_SBOX":  TaintLabel.PUBLIC,
        })

        fn  = MockFunction("aes_sbox_kernel")
        bb  = MockBasicBlock("entry")

        sbox    = MockValue("AES_SBOX")
        idx     = MockValue("idx")
        sbox_addr_val = MockValue("sbox_addr")

        gep  = MockGetElementPtrInst("gep_sbox", base_ptr=sbox, indices=[idx],
                                     source_loc="aes_sbox.c:18:14")
        load = MockLoadInst("sub_byte", ptr_operand=sbox_addr_val,
                            source_loc="aes_sbox.c:18:5")

        bb.add_instruction(gep)
        bb.add_instruction(load)
        fn.add_basic_block(bb)

        violations = self.detector.detect_violations(fn, engine.get_taint_map())

        # Both GEP (secret index) and load (secret pointer) are violations
        self.assertGreaterEqual(len(violations), 2)
        types = [v.type for v in violations]
        self.assertEqual(types.count(ViolationType.MEMORY_LEAK), 2)

        gep_v  = next(v for v in violations if v.instruction.name == "gep_sbox")
        load_v = next(v for v in violations if v.instruction.name == "sub_byte")
        self.assertEqual(gep_v.leaking_operand.name,  "idx")
        self.assertEqual(load_v.leaking_operand.name, "sbox_addr")

    # ------------------------------------------------------------------
    # Test 4: mod_exp exponent branching (square-and-multiply pattern)
    # ------------------------------------------------------------------
    def test_mod_exp_exponent_branch(self):
        """
        Simulates TaintEngine propagation for modular exponentiation:
          %exp       (SECRET, secret exponent)
          %bit       = and  %exp, 1      -> SECRET
          %is_one    = icmp %bit, 1      -> SECRET
          br %is_one, multiply, square   -> BRANCH_LEAK
        """
        engine = self._make_engine({
            "exp":    TaintLabel.SECRET,
            "bit":    TaintLabel.SECRET,   # and result
            "is_one": TaintLabel.SECRET,   # icmp result
        })

        fn  = MockFunction("mod_exp_kernel")
        bb  = MockBasicBlock("loop_body")

        is_one_val = MockValue("is_one")
        br_inst    = MockBranchInst("exp_br", condition=is_one_val,
                                    source_loc="mod_exp.c:22:9")
        bb.add_instruction(br_inst)
        fn.add_basic_block(bb)

        violations = self.detector.detect_violations(fn, engine.get_taint_map())
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].instruction.name, "exp_br")
        self.assertEqual(violations[0].source_loc, "mod_exp.c:22:9")

    # ------------------------------------------------------------------
    # Test 5: PHI node — secret value from one incoming edge taints result
    # ------------------------------------------------------------------
    def test_phi_node_taint_propagation_to_branch(self):
        """
        Simulates TaintEngine PHI node handling:
          %phi = phi [%secret_val, %bb_secret], [%pub_val, %bb_pub]
          -> TaintEngine marks %phi as SECRET (conservative: any SECRET incoming)
          %cmp = icmp %phi, 0  -> SECRET
          br %cmp, ...         -> BRANCH_LEAK

        The PHI node itself is not inspected by ViolationDetector (it's not a
        branch/load/store/GEP). The downstream branch that uses the PHI result is.
        """
        engine = self._make_engine({
            "secret_val": TaintLabel.SECRET,
            "pub_val":    TaintLabel.PUBLIC,
            "phi":        TaintLabel.SECRET,   # PHI result: tainted by one SECRET input
            "cmp":        TaintLabel.SECRET,   # icmp on tainted PHI
        })

        fn  = MockFunction("phi_test")
        bb1 = MockBasicBlock("merge_block")

        cmp_val = MockValue("cmp")
        br_inst = MockBranchInst("phi_br", condition=cmp_val)
        bb1.add_instruction(br_inst)
        fn.add_basic_block(bb1)

        violations = self.detector.detect_violations(fn, engine.get_taint_map())
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].leaking_operand.name, "cmp")

    # ------------------------------------------------------------------
    # Test 6: Post-transformation — verifyZeroLeaks passes on clean IR
    # ------------------------------------------------------------------
    def test_verify_zero_leaks_after_transformation(self):
        """
        Simulates the state after Member 4's Transformer has rewritten the IR:
          - Secret-dependent branch replaced with select instruction.
          - All remaining instructions use only public addresses.
        The post-transformation taint map no longer marks any address as SECRET.
        verify_zero_leaks() must return True.
        """
        # Post-transform: 'cmp' is now used in a select, not a branch.
        # No br, load, store, or GEP with secret operands remain.
        engine = self._make_engine({
            "secret_val": TaintLabel.SECRET,
            "cmp":        TaintLabel.SECRET,   # still tainted, but no longer in a branch
            "result":     TaintLabel.PUBLIC,
        })

        fn  = MockFunction("transformed_fn")
        bb  = MockBasicBlock("entry")

        # Only instruction is a public load — the branch has been eliminated
        pub_ptr = MockValue("result")
        bb.add_instruction(MockLoadInst("final_load", ptr_operand=pub_ptr))
        fn.add_basic_block(bb)

        ok, leaks = self.detector.verify_zero_leaks(fn, engine.get_taint_map())
        self.assertTrue(ok, "Post-transformation function should have zero leaks")
        self.assertEqual(len(leaks), 0)

    # ------------------------------------------------------------------
    # Test 7: Multi-block function — violations detected across all BBs
    # ------------------------------------------------------------------
    def test_multi_block_violations_detected(self):
        """
        Verifies that detect_violations scans ALL basic blocks, not just
        the entry block. Simulates a function with separate entry, loop,
        and exit blocks where the violation is in the loop block.
        """
        engine = self._make_engine({
            "secret_idx": TaintLabel.SECRET,
            "loop_cond":  TaintLabel.SECRET,
        })

        fn        = MockFunction("multi_block_fn")
        bb_entry  = MockBasicBlock("entry")
        bb_loop   = MockBasicBlock("loop")
        bb_exit   = MockBasicBlock("exit")

        # Entry block: public-only load (no violation)
        bb_entry.add_instruction(MockLoadInst("pub_ld", ptr_operand=MockValue("pub_addr")))

        # Loop block: secret-conditioned branch (violation)
        loop_cond = MockValue("loop_cond")
        bb_loop.add_instruction(MockBranchInst("loop_br", condition=loop_cond))

        # Exit block: clean
        bb_exit.add_instruction(MockLoadInst("exit_ld", ptr_operand=MockValue("result_ptr")))

        fn.add_basic_block(bb_entry)
        fn.add_basic_block(bb_loop)
        fn.add_basic_block(bb_exit)

        violations = self.detector.detect_violations(fn, engine.get_taint_map())
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].type, ViolationType.BRANCH_LEAK)
        self.assertEqual(violations[0].instruction.name, "loop_br")


if __name__ == "__main__":
    unittest.main(verbosity=2)

>>>>>>> Stashed changes
