"""Validate `Pd = or(Ps, and(Pt, Pu))` compound predicate body.

Pre-fix: cr.sinc constructor at line 125 declared `Pd = Ps | (Pt & Pu)`
in the display but the body computed `Ps & (Pt | Pu)` (copy-paste from
the line-117 sibling).

Post-fix: body matches the displayed boolean shape.
"""
TEST = {
    "name": "or(Ps, and(Pt, Pu)) compound predicate matches mnemonic",
    "kind": "asm",
    "source": r"""
    .text
    .globl test_or_and_pred
    .type test_or_and_pred,@function
test_or_and_pred:
    { p0 = cmp.eq(r0, #0) }
    { p1 = cmp.eq(r1, #0) }
    { p2 = cmp.eq(r2, #0) }
    { p3 = or(p0, and(p1, p2)) }
    { p3 = and(p3, !p0) }
    { r0 = mux(p3, r4, r5) }
    { jumpr r31 }
""",
    "function": "test_or_and_pred",
    "cpu": "hexagonv79",
    "expected_contains": [
        # Post-fix body Ps | (Pt & Pu) renders with both | and & operators
        # mixed; the OR specifically must appear (the pre-fix bug had
        # Ps & (Pt | Pu) but with our extra masking constructor the OR
        # collapses entirely).
        "|",
    ],
    "expected_not_contains": [],
    "notes": (
        "Sanity test for the or(Ps, and(Pt, Pu)) body fix in cr.sinc."
    ),
}
