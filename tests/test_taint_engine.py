"""Executable integration tests for the Member 3 analysis pipeline.

Source-contract checks run everywhere. Kernel golden tests run when clang,
opt, and the built member3_pipeline executable are available.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TaintEngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = (ROOT / "src/TaintEngine.cpp").read_text()
        cls.pipeline = (ROOT / "scripts/run_pipeline.py").read_text()

    def test_o0_ir_keeps_functions_and_argument_names(self):
        self.assertIn('"-disable-O0-optnone"', self.pipeline)
        self.assertIn('"-fno-discard-value-names"', self.pipeline)

    def test_pipeline_runs_mem2reg_then_configured_pass(self):
        self.assertLess(self.pipeline.index('"-passes=mem2reg"'),
                        self.pipeline.index('"-load-pass-plugin="'))
        self.assertIn('"-ct-config=" + str(config_file)', self.pipeline)

    def test_pointer_argument_and_gep_rules(self):
        self.assertIn("memoryTaintMap[value] = TaintLabel::SECRET", self.engine)
        gep = self.engine.split('else if (auto *GEP', 1)[1].split('else if (auto *LI', 1)[0]
        self.assertIn("GEP->idx_begin()", gep)
        self.assertNotIn("isSecret(GEP->getPointerOperand())", gep)

    def test_phi_select_memory_keys_and_intrinsic_exclusion(self):
        self.assertIn("dyn_cast<llvm::PHINode>(key)", self.engine)
        self.assertIn("dyn_cast<llvm::SelectInst>(key)", self.engine)
        self.assertIn("isa<llvm::IntrinsicInst>(CB)", self.engine)

    def test_fixed_point_control_flow_and_iteration_counter(self):
        self.assertIn("while (changed)", self.engine)
        self.assertIn("PostDominatorTree", self.engine)
        self.assertIn("getIterationCount()", (ROOT / "src/member3_pipeline.cpp").read_text())


class KernelGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = shutil.which("clang")
        cls.opt = shutil.which("opt")
        cls.runner = ROOT / "build" / ("member3_pipeline.exe" if __import__("os").name == "nt" else "member3_pipeline")
        cls.available = bool(cls.clang and cls.opt and cls.runner.exists())

    def run_kernel(self, kernel):
        source = ROOT / "benchmarks/kernels" / f"{kernel}.c"
        config = ROOT / "benchmarks/configs" / f"{kernel}.json"
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td) / f"{kernel}.ll"
            promoted = Path(td) / f"{kernel}_mem2reg.ll"
            subprocess.run([self.clang, "-S", "-emit-llvm", "-O0", "-Xclang",
                            "-disable-O0-optnone", "-fno-discard-value-names",
                            str(source), "-o", str(raw)], check=True, capture_output=True, text=True)
            subprocess.run([self.opt, "-passes=mem2reg", str(raw), "-S", "-o",
                            str(promoted)], check=True, capture_output=True, text=True)
            result = subprocess.run([str(self.runner), str(promoted), str(config)],
                                    check=False, capture_output=True, text=True)
            self.assertIn("Taint analysis iterations:", result.stdout)
            import re
            match = re.search(r"Taint analysis iterations: (\d+)", result.stdout)
            self.assertIsNotNone(match, result.stdout)
            self.assertGreater(int(match.group(1)), 0)
            return result.stdout

    @unittest.skipUnless(shutil.which("clang") and shutil.which("opt") and
                         (ROOT / "build" / "member3_pipeline").exists() or
                         (ROOT / "build" / "member3_pipeline.exe").exists(),
                         "requires clang, opt, and built member3_pipeline")
    def test_aes_sbox_golden(self):
        output = self.run_kernel("aes_sbox")
        self.assertIn("MEMORY_LEAK", output)
        self.assertNotIn("BRANCH_LEAK", output)

    @unittest.skipUnless(shutil.which("clang") and shutil.which("opt") and
                         ((ROOT / "build" / "member3_pipeline").exists() or
                          (ROOT / "build" / "member3_pipeline.exe").exists()),
                         "requires clang, opt, and built member3_pipeline")
    def test_memcmp_golden(self):
        output = self.run_kernel("memcmp")
        self.assertIn("BRANCH_LEAK", output)
        self.assertNotIn("MEMORY_LEAK", output)

    @unittest.skipUnless(shutil.which("clang") and shutil.which("opt") and
                         ((ROOT / "build" / "member3_pipeline").exists() or
                          (ROOT / "build" / "member3_pipeline.exe").exists()),
                         "requires clang, opt, and built member3_pipeline")
    def test_mod_exp_golden(self):
        output = self.run_kernel("mod_exp")
        self.assertIn("BRANCH_LEAK", output)
        self.assertIn("Taint analysis iterations:", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
