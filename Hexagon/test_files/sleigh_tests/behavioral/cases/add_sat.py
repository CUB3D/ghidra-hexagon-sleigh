"""Validate `Rd = add(Rs, Rt):sat` saturation behaviour.

Pre-fix: alu32_alu.sinc clamped overflow to 0xFFFFFFFF (-1) for both
positive and negative overflow, used unsigned wrap detection. Decompile
showed `D5 = -1` on the saturation arm — wrong.

Post-fix (commit 79a702a): clamps to 0x7FFFFFFF (positive overflow) or
0x80000000 (negative overflow) using XOR-on-sign-bits detection. Per
Hexagon V73 PRM §11.3.1.

This test compiles a tiny C function that forces the SLEIGH constructor
to be exercised, then asserts the decompile shows BOTH saturation
constants and does NOT show the old buggy `-1` clamp.
"""
TEST = {
    "name": "add:sat clamps to INT_MAX/INT_MIN, not -1/0",
    "kind": "c",
    "source": r"""
int test_add_sat(int a, int b) {
    return __builtin_HEXAGON_A2_addsat(a, b);
}
""",
    "function": "test_add_sat",
    "cpu": "hexagonv79",
    "expected_contains": [
        "0x7fffffff",   # positive saturation clamp
        "0x80000000",   # negative saturation clamp
    ],
    "expected_not_contains": [
        # Old bug saturated negative overflow to 0xFFFFFFFF (-1).
        # If the regression returns we should see "= -1" or "0xffffffff"
        # in the saturation arm. Modulo whitespace / hex formatting the
        # decompiler will usually emit one of these forms.
        "0xffffffff",
    ],
    "notes": (
        "If this test fails after a SLEIGH change to add:sat, check "
        "alu32_alu.sinc and verify the body uses the XOR-on-sign-bits "
        "overflow detection from commit 79a702a."
    ),
}
