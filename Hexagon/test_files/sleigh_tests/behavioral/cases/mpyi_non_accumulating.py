"""Validate `Rd = mpyi(Rs, Rt)` is a NON-accumulating multiply.

Pre-fix: xtype_mpy.sinc:62 had the body of `+=mpyi` (`D5 = D5i + Rs*Rt`),
so the non-accumulating mnemonic actually accumulated. The constraint
even pulled in `& D5i`, proving the copy-paste origin.

Post-fix (commit f2694f2): body is `D5 = (sext(Rs) * sext(Rt)):4`, no
accumulation. Per V73 PRM §11.10.

If this test starts failing again, the regression is that the decompile
reads the prior value of D5 — visible as a pattern like
`return param_x * param_y + something`.
"""
TEST = {
    "name": "mpyi is non-accumulating multiply",
    "kind": "c",
    "source": r"""
int test_mpyi(int a, int b) {
    return __builtin_HEXAGON_M2_mpyi(a, b);
}
""",
    "function": "test_mpyi",
    "cpu": "hexagonv79",
    "expected_contains": [
        # Master decomp: `return param_1 + param_1 * param_2;` (the bug —
        # adds an extra param_1). Fixed decomp: `return param_1 * param_2;`
        # (clean). We assert the exact clean form.
        "return param_1 * param_2;",
    ],
    "expected_not_contains": [
        # Pre-fix renders `param_1 + param_1 *` because D5 was read both
        # as input (D5i) and output of the multiply.
        "param_1 + param_1 *",
        "param_1 * param_2 + param_1",
    ],
    "notes": (
        "The interesting assertion here is the absence of an accumulator "
        "read. We rely on the decompiler not emitting `+ in_*` operands; "
        "if the SLEIGH body adds D5_pairi to the multiply result, the "
        "decompiler will pick that up as an unbound input."
    ),
}
