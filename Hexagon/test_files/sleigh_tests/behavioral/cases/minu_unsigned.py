"""Validate `Rd = minu(Rs, Rt)` uses unsigned compare.

Pre-fix: xtype_alu.sinc minu register form used `s<` (signed compare)
to select the smaller value, so a function returning `minu(0x80000000, 1)`
would yield 0x80000000 instead of the correct 1.

Post-fix: uses unsigned `<`.

The decompile of a function that calls __builtin_HEXAGON_A2_minu should
not contain a signed compare on the operands.
"""
TEST = {
    "name": "minu register form uses unsigned compare",
    "kind": "c",
    "source": r"""
unsigned int test_minu(unsigned a, unsigned b) {
    return __builtin_HEXAGON_A2_minu(a, b);
}
""",
    "function": "test_minu",
    "cpu": "hexagonv79",
    "expected_contains": [
        # The function takes `unsigned int` and the body must use unsigned
        # compare; Ghidra renders the function header with `uint` only when
        # the SLEIGH body uses unsigned comparison. With master's `s<` the
        # decompiler infers the function as `int test_minu(int param_1, int param_2)`.
        "uint test_minu(uint param_1,uint param_2)",
    ],
    "expected_not_contains": [
        "int test_minu(int",
    ],
    "notes": (
        "Sanity test for the minu fix in xtype_alu.sinc."
    ),
}
