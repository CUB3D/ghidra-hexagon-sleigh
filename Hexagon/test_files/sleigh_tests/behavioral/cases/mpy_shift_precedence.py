"""Validate accumulating `Rxx += mpy(...) << imm` shift precedence.

Pre-fix: ~30 constructors in xtype_mpy.sinc / xtype_complex.sinc wrote
`D5 = D5i + funccall() << imm`; SLEIGH `<<` has lower precedence than
`+`, so this parsed as `(D5i + funccall()) << imm` — the prior accumulator
was shifted instead of just the product.

Post-fix: parens around the multiply-then-shift.
"""
TEST = {
    "name": "+=mpy(...):<<n shifts the product, not the sum",
    "kind": "asm",
    "source": r"""
    .text
    .globl test_mpyacc_shift
    .type test_mpyacc_shift,@function
test_mpyacc_shift:
    { r1:0 += mpy(r2.l, r3.l):<<1 }
    { jumpr r31 }
""",
    "function": "test_mpyacc_shift",
    "cpu": "hexagonv79",
    "expected_contains": [
        # `param_1 + ... * 2` is the post-fix shape: the prior accumulator
        # (param_1) appears unshifted, the multiply result is what gets
        # shifted (Ghidra simplifies `<<1` to `*2`).
        "param_1 +",
    ],
    "expected_not_contains": [
        # If the regression returns, the prior accumulator gets shifted too,
        # so the decompile would parenthesise `(param_1 + ...) <<` form.
        "(param_1 +",
    ],
    "notes": (
        "Tests the precedence fix in xtype_mpy.sinc (commit c14fb51)."
    ),
}
