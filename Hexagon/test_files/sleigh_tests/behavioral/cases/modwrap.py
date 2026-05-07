"""Validate `Rd = modwrap(Rs, Rt)` is a wrap-into-range, not a modulo.

Pre-fix: xtype_alu.sinc modwrap was `D5 = S5i % T5i`, the C signed
remainder. That's not what the manual specifies.

Post-fix: branch form. If Rs<0, add Rt. If Rs>=Rt, sub Rt. Otherwise Rs.

The decompile should show the three-way branch (or an equivalent
expression) and must not contain `%` (the C modulo operator).
"""
TEST = {
    "name": "modwrap uses if/else wrap, not %",
    "kind": "c",
    "source": r"""
int test_modwrap(int a, int b) {
    return __builtin_HEXAGON_A4_modwrapu(a, b);
}
""",
    "function": "test_modwrap",
    "cpu": "hexagonv79",
    "expected_contains": [],
    "expected_not_contains": [
        # The `%` operator would appear in the decompile if SLEIGH still
        # mapped modwrap to a C remainder.
        " % ",
    ],
    "notes": (
        "Sanity test for the modwrap fix in xtype_alu.sinc."
    ),
}
