"""Validate `memw(Rs+#u6) = #s8` sign-extends the immediate to 32 bits.

Pre-fix: st_byte.sinc EXT_ST_S8 reconstructed the 8-bit signed immediate
at result bit 8 (`<< 8`) and exported it as `*[const]:4` without sign
extension. So `memw(r0+#0)=#-1` stored 0x000000FF instead of 0xFFFFFFFF.

Post-fix: shift to bit 7 plus `imm_13 * 0xFFFFFF80` to sign-extend the
8-bit value to 32 bits.

The decompile of a function that stores -1 should show the constant as
either -1 or 0xffffffff, never 0xff.
"""
TEST = {
    "name": "memw(...)=#-1 stores 0xFFFFFFFF after sign-extension",
    "kind": "asm",
    "source": r"""
    .text
    .globl test_store_neg_imm
    .type test_store_neg_imm,@function
test_store_neg_imm:
    { memw(r0+#0) = #-1 }
    { jumpr r31 }
""",
    "function": "test_store_neg_imm",
    "cpu": "hexagonv79",
    "expected_contains": [
        "0xffffffff",
    ],
    "expected_not_contains": [
        "= 0xff;",
        "= 0xff )",
    ],
    "notes": (
        "If this fails, EXT_ST_S8 in st_byte.sinc has regressed: check "
        "the multiplication by 0xFFFFFF80 is preserved."
    ),
}
