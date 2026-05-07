"""Hexagon SLEIGH behavioural regression tests.

Each test in `cases/*.py` defines a `TEST` dict that compiles a small
C or Hexagon-asm snippet with the QUIC-vendored toolchain, imports
the resulting object into a throwaway Ghidra project, decompiles a
named function, and asserts substrings present (or absent) in the
decompiled C output. The point is to validate semantic SLEIGH fixes
that text-only disasm comparison cannot catch.

Usage:
    py run_behavioral.py            # run every test
    py run_behavioral.py add_sat    # run only the test whose stem matches

Pass `--no-rebuild-sla` to skip recompiling hexagon.slaspec when you've
just done that via run_tests.py. Pass `--keep` to leave the build
artefacts behind for inspection.

Exit code: 0 if every test passed, 1 otherwise.
"""
from __future__ import annotations
import argparse, importlib.util, json, os, pathlib, shutil, subprocess, sys, time

HERE         = pathlib.Path(__file__).resolve().parent
CASES_DIR    = HERE / "cases"
BUILD_DIR    = HERE / ".build"
SHARED       = HERE.parent              # ../sleigh_tests
TOOL_BINDIR  = SHARED / ".toolchain" / ".bindir"
def _find_ghidra_root() -> pathlib.Path:
    """Walk upward from this file looking for support/sleigh.bat."""
    for d in HERE.parents:
        if (d / "support" / ("sleigh.bat" if os.name == "nt" else "sleigh")).exists():
            return d
    raise SystemExit(
        f"could not locate Ghidra installation walking up from {HERE}; "
        "set GHIDRA_INSTALL_DIR explicitly")

GHIDRA_ROOT  = pathlib.Path(os.environ.get("GHIDRA_INSTALL_DIR") or _find_ghidra_root())
SLEIGH_BAT   = GHIDRA_ROOT / "support" / "sleigh.bat"
HEADLESS_BAT = GHIDRA_ROOT / "support" / "analyzeHeadless.bat"
LANG_DIR     = GHIDRA_ROOT / "Ghidra" / "Extensions" / "Hexagon" / "data" / "languages"

EXE = ".exe" if os.name == "nt" else ""

def llvm_bindir() -> pathlib.Path:
    if not TOOL_BINDIR.exists():
        raise SystemExit(
            "LLVM toolchain not found. Run: py ../build_toolchain.py"
        )
    p = pathlib.Path(TOOL_BINDIR.read_text().strip())
    if not (p / f"clang{EXE}").exists():
        raise SystemExit(f"clang missing under {p}; re-run build_toolchain.py")
    return p

def maybe_cmd(args: list[str]) -> list[str]:
    """On Windows, .bat files must be invoked through cmd /c."""
    if os.name == "nt":
        return ["cmd", "/c", *args]
    return args

# ---------------------------------------------------------------------------
# Compile + decompile pipeline
# ---------------------------------------------------------------------------

def compile_source(src_path: pathlib.Path, kind: str, cpu: str,
                   out_obj: pathlib.Path,
                   extra_args: list[str] | None = None) -> tuple[bool, str]:
    bd = llvm_bindir()
    extra = list(extra_args or [])
    if kind == "c":
        cmd = [str(bd / f"clang{EXE}"), "--target=hexagon-unknown-linux-musl",
               f"-mcpu={cpu}", "-O0", "-c", "-o", str(out_obj), str(src_path),
               "-fno-asynchronous-unwind-tables", *extra]
    elif kind == "asm":
        cmd = [str(bd / f"llvm-mc{EXE}"), "--triple=hexagon", f"--mcpu={cpu}",
               "--filetype=obj", "-o", str(out_obj), str(src_path), *extra]
    else:
        return False, f"unknown kind: {kind}"
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()
    return True, ""

def ghidra_decompile(obj_path: pathlib.Path, function: str,
                     base_addr: int) -> dict:
    """Import the object via headless, decompile `function`, return JSON."""
    BUILD_DIR.mkdir(exist_ok=True)
    # Use a per-object project directory so concurrent / sequential tests
    # don't trip on stale lock files. Project name = stem of the .o path.
    proj_dir = BUILD_DIR / f"ghidra_proj_{obj_path.stem}"
    if proj_dir.exists():
        shutil.rmtree(proj_dir, ignore_errors=True)
    proj_dir.mkdir(parents=True, exist_ok=True)
    out_json = (BUILD_DIR / f"decomp_{obj_path.stem}.json").resolve()
    if out_json.exists(): out_json.unlink()
    # Tell Ghidra to import as ELF (or Binary if it doesn't parse). Hexagon
    # .o is a real ELF object so the ELF loader works fine.
    args = [
        str(HEADLESS_BAT), str(proj_dir), "tmp",
        "-import", str(obj_path),
        "-processor", "QDSP6:LE:32:default",
        "-postScript", "BehavioralDecomp.java", str(out_json), function,
        "-scriptPath", str(HERE),
        "-deleteProject",
    ]
    r = subprocess.run(maybe_cmd(args), capture_output=True, text=True,
                       timeout=600)
    if not out_json.exists():
        return {"_error": "Ghidra failed to produce JSON",
                "_stdout_tail": r.stdout[-1500:],
                "_stderr_tail": r.stderr[-500:]}
    return json.loads(out_json.read_text())

# ---------------------------------------------------------------------------
# Test discovery + execution
# ---------------------------------------------------------------------------

def load_tests(filter_stem: str | None) -> list[dict]:
    tests = []
    for f in sorted(CASES_DIR.glob("*.py")):
        if f.name == "__init__.py": continue
        if filter_stem and filter_stem not in f.stem: continue
        spec = importlib.util.spec_from_file_location(f.stem, f)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if not hasattr(mod, "TEST"):
            print(f"  skip {f.name}: no TEST defined")
            continue
        t = dict(mod.TEST)
        t["_file"] = f
        tests.append(t)
    return tests

def run_test(t: dict) -> tuple[str, str]:
    BUILD_DIR.mkdir(exist_ok=True)
    src_ext  = ".c" if t["kind"] == "c" else ".s"
    src_path = BUILD_DIR / (t["_file"].stem + src_ext)
    src_path.write_text(t["source"])
    obj_path = BUILD_DIR / (t["_file"].stem + ".o")
    cpu      = t.get("cpu", "hexagonv79")
    ok, err = compile_source(src_path, t["kind"], cpu, obj_path,
                             extra_args=t.get("extra_args"))
    if not ok:
        return "ERROR", f"compile failed: {err[:300]}"
    res = ghidra_decompile(obj_path, t["function"],
                           t.get("base_addr", 0x1000))
    if "_error" in res:
        return "ERROR", res["_error"]
    if not res.get("found", False):
        return "FAIL", f"function {t['function']!r} not found in decompile"
    decomp = res.get("decomp", "")
    decomp_lc = decomp.lower()
    for needle in t.get("expected_contains", []):
        if needle.lower() not in decomp_lc:
            snippet = "\n      ".join(decomp.splitlines()[:30])
            return "FAIL", f"missing {needle!r}\n    decomp:\n      {snippet}"
    for needle in t.get("expected_not_contains", []):
        if needle.lower() in decomp_lc:
            snippet = "\n      ".join(decomp.splitlines()[:30])
            return "FAIL", f"unexpected {needle!r}\n    decomp:\n      {snippet}"
    return "PASS", t.get("name", t["_file"].stem)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def compile_sleigh() -> None:
    print("# Recompiling hexagon.slaspec ...")
    t0 = time.time()
    args = [str(SLEIGH_BAT), "-a", str(LANG_DIR)]
    r = subprocess.run(maybe_cmd(args), capture_output=True, text=True,
                       timeout=300)
    elapsed = time.time() - t0
    ok = r.returncode == 0 and "successfully compiled" in r.stdout
    if not ok:
        print(f"  FAILED ({elapsed:.1f}s)")
        print(r.stdout); print(r.stderr)
        sys.exit(2)
    print(f"  OK ({elapsed:.1f}s)")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("filter", nargs="?",
                    help="only run tests whose filename stem matches this")
    ap.add_argument("--no-rebuild-sla", action="store_true")
    ap.add_argument("--keep", action="store_true",
                    help="don't clean .build/ between tests")
    args = ap.parse_args()

    if not args.no_rebuild_sla:
        compile_sleigh()

    tests = load_tests(args.filter)
    print(f"\n# Running {len(tests)} behavioural test(s) ...\n")
    pass_n = fail_n = err_n = 0
    for t in tests:
        result, detail = run_test(t)
        marker = {"PASS": "  PASS  ", "FAIL": "  FAIL  ", "ERROR": "  ERROR "}[result]
        print(f"{marker}{t['_file'].stem}: {detail}")
        if result == "PASS": pass_n += 1
        elif result == "FAIL": fail_n += 1
        else: err_n += 1
    print(f"\n=== {pass_n} passed, {fail_n} failed, {err_n} errors ===")
    return 0 if (fail_n == 0 and err_n == 0) else 1

if __name__ == "__main__":
    sys.exit(main())
