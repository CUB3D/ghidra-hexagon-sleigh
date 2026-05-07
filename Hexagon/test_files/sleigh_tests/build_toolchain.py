"""Build a Hexagon-only LLVM from source.

Builds clang + llvm-mc + llvm-objdump with the Hexagon target only — the
minimum needed by the SLEIGH test framework (compile C / assemble asm /
disassemble objects):

  ~10-20 min build
  ~150 MB output
  ~600 MB sparse source checkout

We never link a Hexagon binary, so libc/libc++/compiler-rt aren't needed.

Pin the LLVM ref via env var (defaults to llvmorg-22.1.4):
    HEXAGON_LLVM_REF=llvmorg-22.1.5 py build_toolchain.py
    HEXAGON_LLVM_REF=main           py build_toolchain.py

Reuse a local LLVM source tree instead of cloning:
    HEXAGON_LLVM_SRC=/path/to/llvm-project py build_toolchain.py

Requirements:
  - git
  - cmake >= 3.20
  - ninja
  - C++17 toolchain (MSVC 19.30+, clang 12+, or gcc 9+)

After running, `clang[.exe]`, `llvm-mc[.exe]`, `llvm-objdump[.exe]` live
under `.toolchain/build/bin/`. The path is written to `.toolchain/.bindir`.
Idempotent: re-running with the same ref skips both clone and rebuild.

Usage: [HEXAGON_LLVM_REF=<ref>] [HEXAGON_LLVM_SRC=<path>] py build_toolchain.py [--force] [--jobs N]
"""
from __future__ import annotations
import argparse
import os
import pathlib
import platform
import shutil
import subprocess
import sys

HERE      = pathlib.Path(__file__).resolve().parent
TOOL_DIR  = HERE / ".toolchain"
SRC_DIR   = TOOL_DIR / "llvm-project"
BUILD_DIR = TOOL_DIR / "build"
MARKER    = TOOL_DIR / ".complete"
BINDIR_F  = TOOL_DIR / ".bindir"
REF_F     = TOOL_DIR / ".ref"

DEFAULT_REF = os.environ.get("HEXAGON_LLVM_REF", "llvmorg-22.1.4")
REPO_URL    = "https://github.com/llvm/llvm-project.git"

# Sparse-checkout subset that suffices for clang + llvm-mc + llvm-objdump
# with Hexagon-only target. Listing nested paths (rather than the top-level
# "llvm" / "clang") drops the test/unittest/example trees, which together
# weigh hundreds of MB and contain Windows-MAX_PATH-busting filenames.
SPARSE_PATHS = [
    # llvm side
    "llvm/lib", "llvm/include", "llvm/cmake", "llvm/utils",
    "llvm/tools", "llvm/projects", "llvm/runtimes",
    # clang side: clang/CMakeLists.txt has unconditional add_subdirectory()
    # for runtime/ and examples/, so we have to ship those directories even
    # though we don't actually build anything inside them.
    "clang/lib", "clang/include", "clang/cmake", "clang/tools",
    "clang/utils", "clang/runtime", "clang/examples",
    # top-level
    "cmake",
    "third-party",
]

# Always pass these to git to dodge Windows MAX_PATH and to keep checkouts
# stable across machines.
GIT_GLOBAL_OPTS = [
    "-c", "core.longpaths=true",
    "-c", "core.autocrlf=false",
    "-c", "core.symlinks=false",
]

def need(cmd: str) -> str:
    p = shutil.which(cmd)
    if p:
        return p
    raise SystemExit(
        f"required tool '{cmd}' not on PATH. Install it (cmake, ninja, "
        f"git, MSVC/clang/gcc as appropriate) and retry."
    )

def run(cmd: list[str], cwd: pathlib.Path | None = None) -> None:
    print(f"  $ {' '.join(str(c) for c in cmd)}", flush=True)
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(str(c) for c in cmd)}")

def fetch_source(ref: str) -> pathlib.Path:
    override = os.environ.get("HEXAGON_LLVM_SRC")
    if override:
        p = pathlib.Path(override).resolve()
        if not (p / "llvm" / "CMakeLists.txt").exists():
            raise SystemExit(
                f"HEXAGON_LLVM_SRC={p} does not look like an llvm-project tree "
                f"(no llvm/CMakeLists.txt)"
            )
        print(f"  using existing source at {p}")
        return p

    git = need("git")
    g = lambda *args: [git, *GIT_GLOBAL_OPTS, *args]
    if SRC_DIR.exists():
        cur = subprocess.check_output(
            g("describe", "--tags", "--exact-match"),
            cwd=SRC_DIR, stderr=subprocess.DEVNULL, text=True
        ).strip() if (SRC_DIR / ".git").exists() else ""
        if cur == ref:
            print(f"  source already at {ref}")
            return SRC_DIR
        print(f"  switching source from {cur or '?'} to {ref}")
        run(g("fetch", "--depth", "1", "origin", "tag", ref), cwd=SRC_DIR)
        run(g("checkout", ref), cwd=SRC_DIR)
        return SRC_DIR

    print(f"  shallow-cloning {REPO_URL} @ {ref} (sparse) ...")
    SRC_DIR.parent.mkdir(parents=True, exist_ok=True)
    run(g("clone", "--no-checkout", "--filter=blob:none",
          "--depth", "1", "--branch", ref, REPO_URL, str(SRC_DIR)))
    run(g("sparse-checkout", "init", "--cone"), cwd=SRC_DIR)
    run(g("sparse-checkout", "set", *SPARSE_PATHS), cwd=SRC_DIR)
    run(g("checkout"), cwd=SRC_DIR)
    return SRC_DIR

def configure(src: pathlib.Path, build: pathlib.Path) -> None:
    cmake = need("cmake")
    need("ninja")
    args = [
        cmake, "-G", "Ninja",
        "-S", str(src / "llvm"),
        "-B", str(build),
        "-DCMAKE_BUILD_TYPE=Release",
        # Project subset
        "-DLLVM_ENABLE_PROJECTS=clang",
        "-DLLVM_TARGETS_TO_BUILD=Hexagon",
        # Trim everything else
        "-DLLVM_ENABLE_ASSERTIONS=OFF",
        "-DLLVM_BUILD_EXAMPLES=OFF",
        "-DLLVM_INCLUDE_EXAMPLES=OFF",
        "-DLLVM_BUILD_TESTS=OFF",
        "-DLLVM_INCLUDE_TESTS=OFF",
        "-DLLVM_BUILD_BENCHMARKS=OFF",
        "-DLLVM_INCLUDE_BENCHMARKS=OFF",
        "-DLLVM_BUILD_DOCS=OFF",
        "-DLLVM_INCLUDE_DOCS=OFF",
        "-DLLVM_ENABLE_OCAMLDOC=OFF",
        "-DLLVM_ENABLE_BINDINGS=OFF",
        "-DLLVM_ENABLE_TERMINFO=OFF",
        "-DLLVM_ENABLE_LIBXML2=OFF",
        "-DLLVM_ENABLE_ZLIB=OFF",
        "-DLLVM_ENABLE_ZSTD=OFF",
        "-DLLVM_ENABLE_LIBEDIT=OFF",
        "-DLLVM_BUILD_RUNTIME=OFF",
        "-DLLVM_BUILD_RUNTIMES=OFF",
        # Clang trim
        "-DCLANG_ENABLE_ARCMT=OFF",
        "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
        "-DCLANG_PLUGIN_SUPPORT=OFF",
        # Faster TableGen on multi-core hosts
        "-DLLVM_OPTIMIZED_TABLEGEN=ON",
    ]
    # Match the QUIC default of disabling exceptions/RTTI in tools we don't need.
    if platform.system() == "Windows":
        # MSVC needs explicit Release runtime to keep the binary lean.
        args.append("-DLLVM_USE_CRT_RELEASE=MT")
    run(args)

def build(build: pathlib.Path, jobs: int) -> None:
    ninja = need("ninja")
    targets = ["clang", "llvm-mc", "llvm-objdump"]
    cmd = [ninja, "-C", str(build), f"-j{jobs}", *targets]
    run(cmd)

def find_bindir(build: pathlib.Path) -> pathlib.Path:
    bindir = build / "bin"
    exe = ".exe" if os.name == "nt" else ""
    needed = [f"clang{exe}", f"llvm-mc{exe}", f"llvm-objdump{exe}"]
    missing = [n for n in needed if not (bindir / n).exists()]
    if missing:
        raise SystemExit(f"build finished but missing: {missing} under {bindir}")
    return bindir

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                    help="rebuild even if marker is present")
    ap.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 4,
                    help="parallel build jobs (default: cpu_count)")
    args = ap.parse_args(argv[1:])

    ref = DEFAULT_REF
    if MARKER.exists() and not args.force:
        prev_ref = REF_F.read_text().strip() if REF_F.exists() else ""
        bindir = pathlib.Path(BINDIR_F.read_text().strip()) if BINDIR_F.exists() else None
        ok = bindir and bindir.exists() and prev_ref == ref
        exe = ".exe" if os.name == "nt" else ""
        if ok and (bindir / f"clang{exe}").exists():
            print(f"toolchain already built at {bindir} (ref={prev_ref})")
            return 0
        print(f"marker present but stale (ref={prev_ref!r} want {ref!r}) — rebuilding")

    if args.force and BUILD_DIR.exists():
        print(f"--force: removing {BUILD_DIR}")
        shutil.rmtree(BUILD_DIR)

    TOOL_DIR.mkdir(exist_ok=True)
    src = fetch_source(ref)
    BUILD_DIR.mkdir(exist_ok=True)
    configure(src, BUILD_DIR)
    build(BUILD_DIR, args.jobs)
    bindir = find_bindir(BUILD_DIR)
    BINDIR_F.write_text(str(bindir))
    REF_F.write_text(ref)
    MARKER.touch()
    print(f"\n  built clang / llvm-mc / llvm-objdump at {bindir}")
    print(f"  ref:    {ref}")
    print(f"  marker: {MARKER}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
