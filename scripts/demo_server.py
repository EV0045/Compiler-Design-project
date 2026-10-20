#!/usr/bin/env python3
"""Local web demo for the constant-time pass.

Usage: python3 scripts/demo_server.py [--port 8000]
Needs clang/opt on PATH (macOS: export PATH=/opt/homebrew/opt/llvm/bin:$PATH)
and a built plugin in build/.
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNELS = ROOT / "benchmarks" / "kernels"
CONFIGS = ROOT / "benchmarks" / "configs"
REFERENCE = ROOT / "benchmarks" / "reference"
FRONTEND = ROOT / "frontend"
METRICS = ROOT / "results" / "regression_metrics.json"
PERF    = ROOT / "results" / "performance_benchmarks.json"

# Reasons a kernel is not transformed by the local CFG pass
WHY_UNCHANGED = {
    "memcmp": (
        "early-exit loop detected",
        "secret_memcmp returns early when bytes differ, creating secret-dependent "
        "control flow that our CFG-level pass cannot safely eliminate. "
        "A hand-written branchless OR/XOR loop is used as the reference implementation."
    ),
    "mod_exp": (
        "unsafe integer division",
        "mod_exp uses \u2018%\u2019 (urem) with a secret operand. Replacing the "
        "branch over this with a masked select is unsafe without knowing the "
        "divisor is non-zero at compile time. A fixed-iteration bitmask loop "
        "is provided as the reference implementation."
    ),
}


def find_plugin():
    for name in ("libConstantTimePass.so", "libConstantTimePass.dylib",
                 "ConstantTimePass.dll", "libConstantTimePass.dll"):
        p = ROOT / "build" / name
        if p.exists():
            return p
    return None


def sh(cmd, log):
    log.append("$ " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    out = (r.stdout + r.stderr).strip()
    if out:
        log.append(out)
    return r.returncode, out


def list_kernels():
    out = []
    for c in sorted(KERNELS.glob("*.c")):
        cfg = CONFIGS / (c.stem + ".json")
        ref = REFERENCE / (c.stem + "_ct.c")
        why = WHY_UNCHANGED.get(c.stem)
        out.append({
            "name": c.stem,
            "source": c.read_text(),
            "config": json.loads(cfg.read_text()) if cfg.exists() else None,
            "reference_source": ref.read_text() if ref.exists() else None,
            "why_unchanged_short": why[0] if why else None,
            "why_unchanged_long": why[1] if why else None,
        })
    return out


def get_reference(kernel_name):
    ref = REFERENCE / (kernel_name + "_ct.c")
    if not ref.exists():
        return None
    return ref.read_text()


def run_pass(body):
    plugin = find_plugin()
    if plugin is None:
        return {"ok": False, "error": "Plugin not built. Run: cmake --build build"}
    if not shutil.which("clang") or not shutil.which("opt"):
        return {"ok": False, "error": "clang/opt not on PATH. On macOS: "
                "export PATH=/opt/homebrew/opt/llvm/bin:$PATH"}
    cfg = {
        "function": body["function"],
        "secret_parameters": body.get("secret_parameters", []),
        "public_parameters": body.get("public_parameters", []),
    }
    log = []
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "k.c").write_text(body["source"])
        (d / "k.json").write_text(json.dumps(cfg))
        rc, _ = sh(["clang", "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone",
                    "-fno-discard-value-names", d / "k.c", "-o", d / "in.ll"], log)
        if rc:
            return {"ok": False, "error": "clang failed", "log": "\n".join(log)}
        rc, _ = sh(["opt", "-passes=mem2reg", d / "in.ll", "-S", "-o", d / "in.ll"], log)
        if rc:
            return {"ok": False, "error": "mem2reg failed", "log": "\n".join(log)}
        rc, out = sh(["opt", f"-load-pass-plugin={plugin}", "-passes=constant-time-pass",
                      f"-ct-config={d / 'k.json'}", d / "in.ll", "-S", "-o", d / "out.ll"], log)
        if rc:
            return {"ok": False, "error": "pass failed", "log": "\n".join(log)}
        vrc, vout = sh(["opt", "-passes=verify", d / "out.ll", "-disable-output"], log)
        before, after = (d / "in.ll").read_text(), (d / "out.ll").read_text()
    stages = [l.strip() for l in out.splitlines() if l.startswith(("TRANSFORMER", "CT verification"))]
    changed = before != after
    kernel_name = body.get("kernel_name", "")
    why = WHY_UNCHANGED.get(kernel_name) if not changed else None
    return {
        "ok": True,
        "before": before,
        "after": after,
        "changed": changed,
        "ir_valid": vrc == 0,
        "ct_verified": any("CT verification passed" in l for l in stages),
        "stages": stages,
        "log": "\n".join(log),
        "why_unchanged_short": why[0] if why else None,
        "why_unchanged_long": why[1] if why else None,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, data, ctype="application/json"):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (FRONTEND / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/kernels":
            self._send(200, list_kernels())
        elif self.path == "/api/metrics":
            self._send(200, json.loads(METRICS.read_text()) if METRICS.exists() else {})
        elif self.path == "/api/perf":
            self._send(200, json.loads(PERF.read_text()) if PERF.exists() else {})
        elif self.path.startswith("/api/reference/"):
            name = self.path.split("/")[-1]
            src = get_reference(name)
            if src:
                self._send(200, {"source": src})
            else:
                self._send(404, {"error": "no reference for " + name})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/run":
            return self._send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            # forward the kernel name so run_pass can look up why_unchanged
            self._send(200, run_pass(body))
        except Exception as e:
            self._send(500, {"ok": False, "error": str(e)})

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    print(f"Demo at http://127.0.0.1:{args.port}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
