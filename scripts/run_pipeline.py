import subprocess
import sys
from pathlib import Path


def run_command(command):
    print("Running:", " ".join(command))
    result = subprocess.run(command)

    if result.returncode != 0:
        print("Command failed.")
        sys.exit(result.returncode)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/run_pipeline.py <kernel.c>")
        sys.exit(1)

    source_file = Path(sys.argv[1])

    if not source_file.exists():
        print("File not found:", source_file)
        sys.exit(1)

    build_dir = Path("build")
    plugin = build_dir / "libConstantTimePass.so"

    if not plugin.exists():
        print("Plugin not found:", plugin)
        print("Run: cmake --build build")
        sys.exit(1)

    input_ir = source_file.with_suffix(".ll")
    output_ir = source_file.with_name(source_file.stem + "_out.ll")

    run_command([
        "clang",
        "-S",
        "-emit-llvm",
        "-O0",
        str(source_file),
        "-o",
        str(input_ir)
    ])

    run_command([
        "opt",
        "-load-pass-plugin=" + str(plugin),
        "-passes=constant-time-pass",
        str(input_ir),
        "-S",
        "-o",
        str(output_ir)
    ])

    print()
    print("Pipeline completed successfully.")
    print("Input IR :", input_ir)
    print("Output IR:", output_ir)


if __name__ == "__main__":
    main()
