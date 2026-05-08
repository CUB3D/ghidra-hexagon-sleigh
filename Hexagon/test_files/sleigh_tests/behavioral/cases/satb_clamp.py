"""Validate `Rd = satb(Rs)` saturates to signed-8 range, not 0.

Pre-fix: xtype_perm.sinc satb clamped negative-overflow to 0 instead of
0xFFFFFF80 (-128).

Post-fix: clamps to 0xFFFFFF80 / 0x7F.
"""
TEST = {
    "name": "satb clamps to 0xFFFFFF80, not 0, on negative overflow",
    "kind": "c",
    "source": r"""
int test_satb(int a) {
    return __builtin_HEXAGON_A2_satb(a);
}
""",
    "function": "test_satb",
    "cpu": "hexagonv79",
    "expected_contains": [
        "-0x80",
        "0x7f",
    ],
    "expected_not_contains": [
        "= 0;",
    ],
    "notes": (
        "Sanity test for the satb low-clamp fix in xtype_perm.sinc."
    ),
}
