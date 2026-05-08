# Behavioral regression tests for the Hexagon SLEIGH plugin

A test asserts that, after a SLEIGH change, **decompiling a known input
produces an output that matches the documented semantics** — not just
that the disassembly text is right. Each test pins one specific bug fix
or one specific instruction's pcode body.

## How a test works

1. A test case is a Python file in `cases/` defining a `TEST` dict:
   - `name`: human-readable label
   - `source`: either a string of C (with optional inline asm) or a
     string of Hexagon assembly. The runner picks the language from
     the `kind` field.
   - `kind`: `"c"` or `"asm"`.
   - `function`: the function in the compiled output to decompile.
   - `expected_contains`: list of substrings that MUST appear in the
     decompiled C output (case-insensitive).
   - `expected_not_contains`: substrings that MUST NOT appear. Useful
     for "the OLD bug clamped to 0; verify that doesn't reappear".
   - `notes`: free-form context for whoever has to debug a regression.

2. The runner (`run_behavioral.py`):
   - Compiles each `.c` or `.s` source via the QUIC `clang` /
     `llvm-mc` already in `.toolchain/` (the LLVM-MC framework set
     this up).
   - Imports the resulting object via Ghidra headless.
   - Decompiles the named function.
   - Asserts every `expected_contains` substring is present and every
     `expected_not_contains` substring is absent.
   - Prints PASS / FAIL with a snippet of the actual decompile when
     a check fails.

## Why this is in addition to the LLVM-MC oracle

`run_tests.py` (the LLVM-MC oracle) compares **disassembly text** —
catches mnemonic + operand-order bugs but is blind to semantic bugs
where the disassembly looks fine but the pcode body computes the
wrong thing (e.g. our `add:sat` clamping to `-1` instead of
`INT_MAX`, our `or(a, and(b,c))` body that actually computed
`and(a, or(b,c))`).

A behavioral test catches *exactly* those: the decompile of an
`add:sat` body should have `0x7fffffff` and `0x80000000` somewhere; if
it has `0xffffffff` we know the semantic regressed.

## Adding a test

Drop a Python file into `cases/`. Run:
```
py run_behavioral.py             # all tests
py run_behavioral.py add_sat     # match by stem
```

Tests are independent — each compiles a single C/asm snippet, and
each gets its own throwaway Ghidra project.
