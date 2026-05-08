"""Validate the bit-reversed effective address preserves base[31:16].

Pre-fix: ld/st `:brev` constructors built the EA as
`zext(rx_h | rx_l)` where rx_h = S5i(2) (the upper 2 bytes treated as a
16-bit value!) and rx_l = brev(S5i:2). Per V73 PRM the EA must be the
original Rs with only the low 16 bits bit-reversed; the upper 16 bits
should pass through unchanged.

Post-fix (via brev_ea macro): EA = (S5 & 0xFFFF0000) | zext(brev(S5:2)).

To force the bug into the decompile we have to actually USE the loaded
value (not just post-increment). The function loads via the brev EA and
returns the loaded word, so the decompiler renders the EA expression as
part of the address computation. Master shows a degenerate EA without
the 0xffff0000 mask; fixed shows the mask explicitly.
"""
TEST = {
    "name": "brev load EA preserves upper 16 bits of base register",
    "kind": "asm",
    "source": r"""
    .text
    .globl test_brev_load
    .type test_brev_load,@function
test_brev_load:
    { r2 = memw(r0++m0:brev) }
    { r0 = r2 }
    { jumpr r31 }
""",
    "function": "test_brev_load",
    "cpu": "hexagonv79",
    "expected_contains": [
        # Fixed renders the EA mask explicitly: `(param_1 & 0xffff0000)`.
        "0xffff0000",
    ],
    "expected_not_contains": [],
    "notes": (
        "With master's broken EA the decompile shows `zext(...)` of a "
        "16-bit expression without the 0xffff0000 mask, so the load "
        "appears to read from a tiny low-memory address."
    ),
}
