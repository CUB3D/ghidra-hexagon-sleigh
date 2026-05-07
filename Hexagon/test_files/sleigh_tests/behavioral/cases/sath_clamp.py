"""Validate `Rd = sath(Rs)` saturates to signed-16 range, not 0.

Pre-fix: xtype_perm.sinc sath clamped negative-overflow to 0 instead of
the signed minimum 0xFFFF8000 (-32768). So sath(-100000) returned 0
instead of -32768.

Post-fix: clamps to 0xFFFF8000 on the low side, 0x7FFF on the high side.

The decompile of __builtin_HEXAGON_A2_sath should reference the signed-
16 minimum constant.
"""
TEST = {
    "name": "sath clamps to 0xFFFF8000, not 0, on negative overflow",
    "kind": "c",
    "source": r"""
int test_sath(int a) {
    return __builtin_HEXAGON_A2_sath(a);
}
""",
    "function": "test_sath",
    "cpu": "hexagonv79",
    "expected_contains": [
        "-0x8000",
        "0x7fff",
    ],
    "expected_not_contains": [
        "= 0;",
    ],
    "notes": (
        "Sanity test for the sath low-clamp fix in xtype_perm.sinc."
    ),
}
