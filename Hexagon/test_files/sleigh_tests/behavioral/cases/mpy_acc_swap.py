"""Validate `Rxx += mpyu(Rs, Rt)` uses unsigned (zext) operands.

Pre-fix: xtype_mpy.sinc had `+=mpy` and `+=mpyu` semantic bodies swapped:
`+=mpy` used zext (so accumulated an unsigned product) and `+=mpyu`
used sext (so accumulated a signed product).

Post-fix: `+=mpy` uses sext, `+=mpyu` uses zext.
"""
TEST = {
    "name": "+=mpyu accumulates an unsigned product",
    "kind": "asm",
    "source": r"""
    .text
    .globl test_mpyu_acc
    .type test_mpyu_acc,@function
test_mpyu_acc:
    { r1:0 += mpyu(r2, r3) }
    { r0 = r1 }
    { jumpr r31 }
""",
    "function": "test_mpyu_acc",
    "cpu": "hexagonv79",
    "expected_contains": [
        # Fixed: `(ulonglong)param_1 * (ulonglong)param_2`.
        # Master: `(longlong)param_1 * (longlong)param_2`.
        # Both forms have a `(ulonglong)` cast on the >> shift, so we check
        # the operand cast specifically.
        "(ulonglong)param_1 * (ulonglong)param_2",
    ],
    "expected_not_contains": [
        # Pre-fix uses signed casts on the operands.
        "(longlong)param_1 * (longlong)param_2",
    ],
    "notes": (
        "Sanity test for the +=mpy / +=mpyu zext/sext swap in xtype_mpy.sinc."
    ),
}
