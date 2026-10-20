import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLUGIN = PROJECT_ROOT / "build" / "libConstantTimePass.so"


class TestConstantTimeTransformer(unittest.TestCase):

    def run_opt(self, source_code, config):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)

            source = temp / "test.c"
            config_file = temp / "config.json"
            input_ir = temp / "input.ll"
            output_ir = temp / "output.ll"

            source.write_text(source_code)
            config_file.write_text(config)

            subprocess.run(
                [
                    "clang",
                    "-S",
                    "-emit-llvm",
                    "-O0",
                    "-Xclang",
                    "-disable-O0-optnone",
                    "-fno-discard-value-names",
                    str(source),
                    "-o",
                    str(input_ir),
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )

            subprocess.run(
                [
                    "opt",
                    "-passes=mem2reg",
                    str(input_ir),
                    "-S",
                    "-o",
                    str(input_ir),
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )

            subprocess.run(
                [
                    "opt",
                    "-load-pass-plugin=" + str(PLUGIN),
                    "-passes=constant-time-pass",
                    "-ct-config=" + str(config_file),
                    str(input_ir),
                    "-S",
                    "-o",
                    str(output_ir),
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )

            return output_ir.read_text()

    def test_secret_branch_transformed_to_select(self):
        source = """
        int test(int secret, int a, int b)
        {
            if (secret)
                return a + 10;
            else
                return b + 20;
        }
        """

        config = """
        {
            "secret_parameters": ["secret"],
            "public_parameters": ["a", "b"]
        }
        """

        output = self.run_opt(source, config)

        self.assertIn("select i1", output)
        self.assertNotIn("br i1 %tobool", output)

    def test_aes_lookup_transformed(self):
        source = """
        #include <stdint.h>

        static const uint8_t sbox[4] = {1, 2, 3, 4};

        uint8_t aes_sbox(uint8_t input)
        {
            return sbox[input];
        }
        """

        config = """
        {
            "secret_parameters": ["input"],
            "public_parameters": []
        }
        """

        output = self.run_opt(source, config)

        self.assertIn("icmp eq", output)
        self.assertIn("sext i1", output)
        self.assertIn("and i8", output)
        self.assertIn("or i8", output)
        self.assertNotIn("load i8, ptr %arrayidx", output)

    def test_mod_exp_unsafe_remainder_keeps_branch(self):
        source = """
        #include <stdint.h>

        uint64_t mod_exp(uint64_t base, uint64_t secret_exp, uint64_t mod)
        {
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
        """

        config = """
        {
            "function": "mod_exp",
            "secret_parameters": ["secret_exp"],
            "public_parameters": ["base", "mod"]
        }
        """

        output = self.run_opt(source, config)

        self.assertIn("urem i64", output)
        self.assertIn("br i1 %tobool", output)


    def test_memcmp_style_function_has_no_early_mismatch_return(self):
        source = """
        int secret_memcmp(
            const unsigned char *a,
            const unsigned char *b,
            int n)
        {
            int mismatch = 0;

            for (int i = 0; i < n; i++) {
                mismatch |= (a[i] != b[i]);
            }

            return mismatch != 0;
        }
        """

        config = """
        {
            "secret_parameters": ["a", "b"],
            "public_parameters": ["n"]
        }
        """

        output = self.run_opt(source, config)

        self.assertIn("define", output)
        self.assertIn("secret_memcmp", output)
        self.assertIn("icmp ne i32", output)
        self.assertIn("or i32", output)
        self.assertIn("br i1 %cmp,", output)
        self.assertNotIn("br i1 %cmp4,", output)

    def test_transformed_ir_is_valid(self):
        source = """
        int test(int secret, int a, int b)
        {
            if (secret)
                return a + 10;
            else
                return b + 20;
        }
        """

        config = """
        {
            "secret_parameters": ["secret"],
            "public_parameters": ["a", "b"]
        }
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)

            source_file = temp / "test.c"
            config_file = temp / "config.json"
            input_ir = temp / "input.ll"
            output_ir = temp / "output.ll"

            source_file.write_text(source)
            config_file.write_text(config)

            subprocess.run(
                [
                    "clang",
                    "-S",
                    "-emit-llvm",
                    "-O0",
                    "-Xclang",
                    "-disable-O0-optnone",
                    "-fno-discard-value-names",
                    str(source_file),
                    "-o",
                    str(input_ir),
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )

            subprocess.run(
                [
                    "opt",
                    "-load-pass-plugin=" + str(PLUGIN),
                    "-passes=constant-time-pass",
                    "-ct-config=" + str(config_file),
                    str(input_ir),
                    "-S",
                    "-o",
                    str(output_ir),
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )

            subprocess.run(
                [
                    "opt",
                    "-passes=verify",
                    str(output_ir),
                    "-disable-output",
                ],
                check=True,
                cwd=PROJECT_ROOT,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
