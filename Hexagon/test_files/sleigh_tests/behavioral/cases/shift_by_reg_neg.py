"""Validate shift-by-register handles negative shift counts.

Pre-fix: xtype_shift.sinc shift-by-register bodies (~44 constructors)
used `D5 = S5i << T5i` (or s>>, etc) directly. Per V73 PRM 11.10.5 the
shamt is `sxt7(Rt[6:0])` and a negative shamt inverts the shift
direction.

Post-fix: helper macros (asl_by_reg_w/d, lsl_by_reg_w/d, asr/lsr) handle
both directions. The decompile should show a branch on the sign of the
shift count.
"""
TEST = {
    "name": "asl by register handles negative shamt",
    "kind": "c",
    "source": r"""
int test_asl_by_reg(int a, int n) {
    return __builtin_HEXAGON_S2_asl_r_r(a, n);
}
""",
    "function": "test_asl_by_reg",
    "cpu": "hexagonv79",
    "expected_contains": [
        # Fixed: shamt = (param_2 << 25) s>> 25 + branch-on-sign.
        # Decompile shows the sxt7 expression and a conditional inverse.
        "(param_2 << 0x19) >> 0x19",
    ],
    "expected_not_contains": [
        # Master simply emits `param_1 << param_2;` with no sxt7 / branch.
        "return param_1 << param_2;",
    ],
    "notes": (
        "Sanity test for the shift-by-reg sxt7 fix in xtype_shift.sinc."
    ),
}
