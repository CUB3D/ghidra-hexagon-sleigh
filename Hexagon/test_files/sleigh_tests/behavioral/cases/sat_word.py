"""Validate `Rd = sat(Rss)` clamps signed-32 range, not 0.

Pre-fix: xtype_perm.sinc sat (saturate-pair-to-word) clamped negative
overflow to 0; comparison was against 0 instead of 0xFFFFFFFF80000000
(the signed-32 minimum sign-extended to 64).

Post-fix: 8-byte signed compares against the proper bounds; clamps to
0x80000000 / 0x7FFFFFFF.
"""
TEST = {
    "name": "sat (Rdd_pair) clamps to 0x80000000 / 0x7FFFFFFF",
    "kind": "c",
    "source": r"""
int test_sat(long long a) {
    return __builtin_HEXAGON_A2_sat(a);
}
""",
    "function": "test_sat",
    "cpu": "hexagonv79",
    "expected_contains": [
        "0x7fffffff",
        "0x80000000",
    ],
    "expected_not_contains": [],
    "notes": (
        "Sanity test for the sat low-clamp fix in xtype_perm.sinc."
    ),
}
