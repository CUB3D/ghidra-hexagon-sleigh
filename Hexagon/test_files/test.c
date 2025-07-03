int main() {
    asm("foo: ");
   asm("{ if(cmp.eq(r4.NEW, r4)) jump:nt foo; r4 = #10; r5=r4; } ");

   asm("{ if(cmp.eq(r0.NEW, #0)) jump:nt foo; r0 = #10; } ");
   asm("{ if(cmp.eq(r1.NEW, #0)) jump:nt foo; r1 = #10; } ");
   asm("{ if(cmp.eq(r2.NEW, #0)) jump:nt foo; r2 = #10; } ");
   asm("{ if(cmp.eq(r3.NEW, #0)) jump:nt foo; r3 = #10; } ");
   asm("{ if(cmp.eq(r4.NEW, #0)) jump:nt foo; r4 = #10; } ");
   asm("{ if(cmp.eq(r5.NEW, #0)) jump:nt foo; r5 = #10; } ");
}
