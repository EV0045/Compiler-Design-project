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
    candidates = [
        build_dir / "libConstantTimePass.so",
        build_dir / "libConstantTimePass.dylib",
        build_dir / "ConstantTimePass.dll",
        build_dir / "libConstantTimePass.dll",
    ]
    plugin = next((candidate for candidate in candidates if candidate.exists()), None)
    if plugin is None:
        print("Plugin not found in", build_dir)
        print("Run: cmake --build build")
        sys.exit(1)

    input_ir = source_file.with_suffix(".ll")
    promoted_ir = source_file.with_name(source_file.stem + "_mem2reg.ll")
    output_ir = source_file.with_name(source_file.stem + "_out.ll")

    run_command([
        "clang",
        "-S",
        "-emit-llvm",
        "-O0",
        "-Xclang",
        "-disable-O0-optnone",
        "-fno-discard-value-names",
        str(source_file),
        "-o",
        str(input_ir)
    ])

    # Promote O0 stack slots so argument origins and SSA/phi flows are visible.
    run_command([
        "opt",
        "-passes=mem2reg",
        str(input_ir),
        "-S",
        "-o",
        str(promoted_ir)
    ])

    config_file = Path("benchmarks/configs") / (source_file.stem + ".json")
    if not config_file.exists():
        print("Config not found:", config_file)
        print("Expected benchmarks/configs/<kernel>.json or run from project root.")
        sys.exit(1)

    run_command([
        "opt",
        "-load-pass-plugin=" + str(plugin),
        "-passes=constant-time-pass",
        "-ct-config=" + str(config_file),
        str(promoted_ir),
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
