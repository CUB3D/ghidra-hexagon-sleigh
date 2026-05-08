# Hexagon SLEIGH plugin sanity tests

Compares the plugin's SLEIGH disassembler against LLVM's official
Hexagon `llvm-mc` / `llvm-objdump` output across the LLVM project's
own Hexagon MC test corpus (vendored under `corpus/llvm/`,
Apache-2.0-with-LLVM-exception).

## Quick start

```
py build_toolchain.py     # one-time: build Hexagon-only LLVM from source
py run_tests.py           # run all corpus tests
py run_tests.py xtype_mpy # run just one .s file
```

You need git, cmake (>=3.20), ninja, and a C++17 toolchain (MSVC,
clang, or gcc). The build is configured with `LLVM_TARGETS_TO_BUILD=Hexagon`
and most LLVM features disabled — ~150 MB output, ~10-20 min on
typical hardware.

## How it works

1. `build_toolchain.py` shallow-clones llvm-project at a pinned tag,
   sparse-checks-out only `llvm/`, `clang/`, `cmake/`, configures with
   the Hexagon target only and trims tests/examples/runtimes/docs/
   bindings/zlib/zstd/etc, then builds `clang`, `llvm-mc`,
   `llvm-objdump`. Pin a different ref via
   `HEXAGON_LLVM_REF=llvmorg-22.1.5`. Reuse an existing checkout via
   `HEXAGON_LLVM_SRC=/path/to/llvm-project`. The script writes
   `.toolchain/.bindir`, which `run_tests.py` reads to find the
   binaries.
2. `run_tests.py`:
   a. Compiles `hexagon.slaspec` via Ghidra's `support/sleigh.bat`.
   b. For each `.s` file in `corpus/llvm/`, calls
      `llvm-mc --triple=hexagon --filetype=obj`, then
      `llvm-objdump -d` — the resulting `(addr, bytes, mnemonic)`
      tuples become the **ground truth**.
   c. Concatenates all expected bytes into a single blob.
   d. Imports the blob into a throwaway Ghidra headless project,
      disassembles, and emits `(addr, bytes, mnemonic)` per
      instruction.
   e. Diffs the two sequences. Any mnemonic mismatch is a bug.

3. The Ghidra side runs against the compiled `hexagon.sla` directly —
   no Ghidra project file, no private binaries.

## Ground truth caveat

LLVM and Ghidra format some operands differently — register pairs
shown as `R5:4` vs `R5_R4`, immediate values as `#0x10` vs `0x10`,
etc. The runner normalizes these before comparing. See
`normalize_mnemonic()` in `run_tests.py` for the exact rules.

When a mismatch is reported and you've confirmed it's a SLEIGH bug,
fix `.sinc` and re-run. When it's a normalization gap, extend
`normalize_mnemonic()`.

## License

The vendored LLVM tests under `corpus/llvm/` are
Apache-2.0-with-LLVM-exception. See `corpus/llvm/LICENSE` for full
attribution.

No toolchain binaries are checked in. `build_toolchain.py` clones
`github.com/llvm/llvm-project` (Apache-2.0-WLE).
