"""Hexagon SLEIGH plugin sanity tests, driven by LLVM as ground truth.

Workflow:
  1. Compile hexagon.slaspec (`support/sleigh.bat -a`).
  2. Locate `llvm-mc` and `llvm-objdump` (run `build_toolchain.py` first).
  3. For each `.s` in `corpus/llvm/`:
       a. Assemble with llvm-mc -> .o
       b. Disassemble with llvm-objdump -> ground-truth (addr, bytes, mnemonic).
  4. Concatenate all .o's .text sections into one blob, import via
     analyzeHeadless, disassemble linearly with a Java script.
  5. Diff Ghidra's per-instruction output against LLVM's. Report mismatches.

Usage:
    py run_tests.py [glob]            # run all corpus tests, or filter by glob
    py run_tests.py xtype_mpy         # run just one .s file
    py run_tests.py --no-rebuild-sla  # skip SLEIGH recompile (faster iteration)
    py run_tests.py --update-corpus   # re-fetch corpus from llvm-project main

Exit code: 0 if all tests pass, 1 otherwise.
"""
from __future__ import annotations
import argparse, json, os, pathlib, re, shutil, subprocess, sys, time
from urllib.request import urlopen

HERE         = pathlib.Path(__file__).resolve().parent
CORPUS_DIR   = HERE / "corpus" / "llvm"
TOOL_BINDIR  = HERE / ".toolchain" / ".bindir"
BUILD_DIR    = HERE / ".build"
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
JAVA_RUNNER  = HERE / "HexagonSleighDisasm.java"

LLVM_RAW_BASE = "https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/test/MC/Hexagon"

EXE = ".exe" if os.name == "nt" else ""

# ---------------------------------------------------------------------------
# Toolchain location
# ---------------------------------------------------------------------------

def llvm_bindir() -> pathlib.Path:
    if not TOOL_BINDIR.exists():
        raise SystemExit(
            "LLVM toolchain not found. Run: py build_toolchain.py"
        )
    p = pathlib.Path(TOOL_BINDIR.read_text().strip())
    if not (p / f"llvm-mc{EXE}").exists():
        raise SystemExit(f"llvm-mc not at {p}; re-run build_toolchain.py")
    return p

def llvm_mc()      -> pathlib.Path: return llvm_bindir() / f"llvm-mc{EXE}"
def llvm_objdump() -> pathlib.Path: return llvm_bindir() / f"llvm-objdump{EXE}"

# ---------------------------------------------------------------------------
# Corpus management
# ---------------------------------------------------------------------------

# Each entry maps a target filename to its LLVM source path. Keep this list
# small and curated to start; expand as more .sinc files are validated.
LLVM_CORPUS_FILES = [
    "instructions/alu32_alu.s",
    "instructions/alu32_perm.s",
    "instructions/alu32_pred.s",
    "instructions/cr.s",
    "instructions/j.s",
    "instructions/jr.s",
    "instructions/ld.s",
    "instructions/memop.s",
    "instructions/nv_j.s",
    "instructions/nv_st.s",
    "instructions/st.s",
    "instructions/system_user.s",
    "instructions/xtype_alu.s",
    "instructions/xtype_bit.s",
    "instructions/xtype_complex.s",
    "instructions/xtype_fp.s",
    "instructions/xtype_mpy.s",
    "instructions/xtype_perm.s",
    "instructions/xtype_pred.s",
    "instructions/xtype_shift.s",
]

def fetch_corpus(force: bool=False) -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    license_path = CORPUS_DIR / "LICENSE"
    if not license_path.exists() or force:
        print("  fetching LLVM Apache-2.0 license attribution ...")
        url = "https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/LICENSE.TXT"
        with urlopen(url, timeout=30) as r:
            license_path.write_bytes(r.read())
    for rel in LLVM_CORPUS_FILES:
        dest = CORPUS_DIR / pathlib.Path(rel).name
        if dest.exists() and not force:
            continue
        url = f"{LLVM_RAW_BASE}/{rel}"
        print(f"  fetching {rel}")
        with urlopen(url, timeout=30) as r:
            dest.write_bytes(r.read())

# ---------------------------------------------------------------------------
# LLVM ground-truth (assemble + disassemble)
# ---------------------------------------------------------------------------

# llvm-objdump output line shape:
# "       0:    01 02 03 04   01020304    mnemonic ops"
# We tolerate variable column widths.
OBJDUMP_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+([0-9a-f]+)\s+(.+?)\s*$",
    re.IGNORECASE,
)

def assemble_and_disasm(src: pathlib.Path,
                        cpu: str = "hexagonv79") -> list[dict]:
    """Returns a list of {addr, bytes_hex, mnemonic, source} per instruction."""
    BUILD_DIR.mkdir(exist_ok=True)
    obj = BUILD_DIR / (src.stem + ".o")
    r = subprocess.run(
        [str(llvm_mc()), "--triple=hexagon", f"--mcpu={cpu}",
         "--filetype=obj", "-o", str(obj), str(src)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return [{"_error": f"llvm-mc failed: {r.stderr.strip()}"}]
    r = subprocess.run(
        [str(llvm_objdump()), "-d", "--triple=hexagon",
         f"--mcpu={cpu}", str(obj)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return [{"_error": f"llvm-objdump failed: {r.stderr.strip()}"}]
    out = []
    for line in r.stdout.splitlines():
        m = OBJDUMP_RE.match(line)
        if not m: continue
        addr = int(m.group(1), 16)
        # bytes shown as hex pairs separated by spaces
        bytes_hex = m.group(2).replace(" ", "")
        mnem = m.group(4).strip()
        out.append({
            "addr": addr,
            "bytes": bytes_hex,
            "mnem": mnem,
        })
    # Read the .text bytes too — needed for the Ghidra side
    return out

def read_text_section(obj: pathlib.Path) -> bytes:
    r = subprocess.run(
        [str(llvm_objdump()), "-s", "-j", ".text", str(obj)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return b""
    bs = bytearray()
    for line in r.stdout.splitlines():
        if not line.startswith(" "): continue
        # " 0000 01020304 ..." each group is 4 bytes hex
        parts = line.split()
        if not parts or not all(c in "0123456789abcdef" for c in parts[0].lower()):
            continue
        for word in parts[1:]:
            if all(c in "0123456789abcdef" for c in word.lower()):
                # word is 8 hex chars (4 bytes) in big-endian display order;
                # llvm-objdump -s shows them as memory bytes left-to-right
                if len(word) == 8:
                    bs += bytes.fromhex(word)
                elif len(word) % 2 == 0:
                    bs += bytes.fromhex(word)
    return bytes(bs)

# ---------------------------------------------------------------------------
# SLEIGH compile
# ---------------------------------------------------------------------------

def compile_sleigh() -> None:
    print("# Compiling hexagon.slaspec ...")
    t0 = time.time()
    args = [str(SLEIGH_BAT), "-a", str(LANG_DIR)]
    if os.name == "nt":
        args = ["cmd", "/c", *args]
    r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    elapsed = time.time() - t0
    ok = r.returncode == 0 and "successfully compiled" in r.stdout
    if not ok:
        print(f"  FAILED ({elapsed:.1f}s)")
        print(r.stdout); print(r.stderr)
        sys.exit(2)
    print(f"  OK ({elapsed:.1f}s)")

# ---------------------------------------------------------------------------
# Ghidra disasm via headless
# ---------------------------------------------------------------------------

def ghidra_disasm(blob: bytes, base_addr: int = 0x1000) -> list[dict]:
    """Import `blob` into a temp Ghidra project at base_addr, disassemble
    linearly, return [{addr, bytes_hex, mnem}, ...]."""
    BUILD_DIR.mkdir(exist_ok=True)
    blob_path  = BUILD_DIR / "blob.bin"
    blob_path.write_bytes(blob)
    proj_dir   = BUILD_DIR / "ghidra_proj"
    proj_dir.mkdir(exist_ok=True)
    # Clean any prior project of same name
    for p in proj_dir.glob("*"):
        if p.is_dir(): shutil.rmtree(p)
        else: p.unlink()
    out_json = BUILD_DIR / "ghidra_disasm.json"
    if out_json.exists(): out_json.unlink()
    args = [
        str(HEADLESS_BAT), str(proj_dir), "tmp",
        "-import", str(blob_path),
        "-loader", "BinaryLoader",
        "-loader-baseAddr", hex(base_addr),
        "-processor", "QDSP6:LE:32:default",
        "-postScript", "HexagonSleighDisasm.java", str(out_json.resolve()),
        "-scriptPath", str(HERE),
        "-deleteProject",
    ]
    # On Windows, .bat files need to be invoked through cmd /c. Avoid
    # `shell=True` because that does not quote list args correctly when
    # paths contain `+` or other shell metacharacters.
    if os.name == "nt":
        args = ["cmd", "/c", *args]
    if os.environ.get("DEBUG_HEADLESS"):
        print("# Running:", " ".join(args))
    r = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if os.environ.get("DEBUG_HEADLESS"):
        print("# stdout tail:")
        print(r.stdout[-3000:])
        print("# stderr tail:")
        print(r.stderr[-1000:])
    if not out_json.exists():
        print("Ghidra failed:")
        print(r.stdout[-3000:]); print(r.stderr[-1500:])
        return []
    return json.loads(out_json.read_text())["instructions"]

# ---------------------------------------------------------------------------
# Mnemonic normalization for cross-tool comparison
# ---------------------------------------------------------------------------

_REG_ALIASES = {
    "sp": "r29", "fp": "r30", "lr": "r31",
    # Pair aliases — LLVM prints r29:28 etc., Ghidra prints SP_R28 / r29_r28
    "sp_r28": "r29_r28", "fp_r29": "r30_r29", "lr_r30": "r31_r30",
}

def normalize_mnem(s: str) -> str:
    s = s.lower().strip()
    # Drop the {...} packet braces — both tools wrap with them but
    # whitespace varies.
    if s.startswith("{"): s = s[1:]
    if s.endswith("}"): s = s[:-1]
    s = s.strip()
    # Collapse all whitespace
    s = re.sub(r"\s+", " ", s)
    # Drop spaces around `,`, `(`, `)`, `=`
    s = re.sub(r"\s*([,()=])\s*", r"\1", s)
    # LLVM `r5:4` (register pair) vs Ghidra `r5_r4` or `r5r4`.
    # Normalize all to `rN_rM`.
    s = re.sub(r"r(\d+):(\d+)", lambda m: f"r{m.group(1)}_r{m.group(2)}", s)
    s = re.sub(r"r(\d+)r(\d+)", lambda m: f"r{m.group(1)}_r{m.group(2)}", s)
    # Map register aliases (sp/fp/lr/pc) to canonical r29/r30/r31.
    for alias, canon in _REG_ALIASES.items():
        s = re.sub(r"\b" + alias + r"\b", canon, s)
    # Strip `#` prefix on immediates.
    s = s.replace("#-", "-")
    s = re.sub(r"#0x", "0x", s)
    s = re.sub(r"#(\d)", r"\1", s)
    return s

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("filter", nargs="?",
        help="only run .s files whose stem matches this (glob)")
    ap.add_argument("--no-rebuild-sla", action="store_true")
    ap.add_argument("--update-corpus", action="store_true")
    ap.add_argument("--cpu", default="hexagonv79")
    args = ap.parse_args()

    if args.update_corpus:
        fetch_corpus(force=True)
    elif not CORPUS_DIR.exists() or not list(CORPUS_DIR.glob("*.s")):
        fetch_corpus()

    if not args.no_rebuild_sla:
        compile_sleigh()

    files = sorted(CORPUS_DIR.glob("*.s"))
    if args.filter:
        files = [f for f in files if args.filter in f.stem]

    # 1) Build per-file expected disassembly + .text bytes
    print(f"\n# Assembling {len(files)} corpus file(s) via llvm-mc ...")
    expected: list[dict] = []   # flattened list across all files
    blob_parts: list[bytes] = []
    blob_offset = 0
    base_addr = 0  # match LLVM's section-relative addressing
    for f in files:
        instrs = assemble_and_disasm(f, args.cpu)
        if instrs and "_error" in instrs[0]:
            print(f"  {f.name:24s} ERROR: {instrs[0]['_error']}")
            continue
        obj_path = BUILD_DIR / (f.stem + ".o")
        text_bytes = read_text_section(obj_path)
        if not text_bytes:
            print(f"  {f.name:24s} empty .text")
            continue
        for ins in instrs:
            ins["src_file"] = f.name
            ins["global_addr"] = base_addr + blob_offset + ins["addr"]
            expected.append(ins)
        blob_parts.append(text_bytes)
        blob_offset += len(text_bytes)
        print(f"  {f.name:24s} {len(instrs):4d} instructions, "
              f"{len(text_bytes):5d} bytes")

    blob = b"".join(blob_parts)
    print(f"\n# Total: {len(expected)} instructions, {len(blob)} bytes blob\n")

    # 2) Run Ghidra disasm on the blob
    print("# Running Ghidra headless disassembler ...")
    actual = ghidra_disasm(blob, base_addr)
    print(f"  got {len(actual)} instructions from Ghidra")

    # 3) Diff
    print("\n# Comparing ...")
    matched = 0
    mismatched: list[tuple] = []
    by_addr = {a["addr"]: a for a in actual}
    for e in expected:
        ga = by_addr.get(e["global_addr"])
        if ga is None:
            mismatched.append((e, None))
            continue
        if normalize_mnem(e["mnem"]) == normalize_mnem(ga["mnem"]):
            matched += 1
        else:
            mismatched.append((e, ga))

    print(f"\n=== {matched} matched, {len(mismatched)} mismatched ===")
    if mismatched:
        print("\nFirst 20 mismatches:")
        for e, ga in mismatched[:20]:
            llvm = e["mnem"]
            ghidra = ga["mnem"] if ga else "<no Ghidra inst>"
            print(f"  {e['src_file']} +{e['addr']:#x} bytes={e['bytes']}")
            print(f"    LLVM:   {llvm}")
            print(f"    Ghidra: {ghidra}")
        if len(mismatched) > 20:
            print(f"  ... and {len(mismatched) - 20} more")

    return 0 if not mismatched else 1

if __name__ == "__main__":
    sys.exit(main())
