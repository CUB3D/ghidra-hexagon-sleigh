//#include <stdlib.h>

extern int rand();
volatile int nope = 0;
int foo() {
    int i = 0;
    while(nope) {
        i += 1;
    }
    return i;
} 

int test_s3_new() {
   //asm("{ if(cmp.eq(r4.NEW, r4)) jump:nt foo; r4 = #10; r5=r4; } ");

   //asm("{ if(cmp.eq(r0.NEW, #0)) jump:nt foo; r0 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #0)) jump:nt foo; r28 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #0)) jump:nt foo; r0=#10; r28 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #0)) jump:nt foo; r1=#20; r0=#10; r28 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #0x1)) jump:nt foo; r1=#20; r0=#10; r28 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #1)) jump:nt foo; r1=#20; r28 = #10; } ");
   //asm("{ if(cmp.eq(r28.NEW, #1)) jump:nt foo; r28 = #10; } ");
   //asm("{ r17:16 = combine(r0, r1); memd(SP+#-0x10) = r17:16; allocframe(#0x10); } ");

  // asm("{ P0 = bitsclr(r9, #0x3); if(!P0.new) r2=#0x100 ; } ");
   /*asm("{ if(cmp.eq(r1.NEW, #0)) jump:nt foo; r1 = #10; } ");
   asm("{ if(cmp.eq(r2.NEW, #0)) jump:nt foo; r2 = #10; } ");
   asm("{ if(cmp.eq(r3.NEW, #0)) jump:nt foo; r3 = #10; } ");
   asm("{ if(cmp.eq(r4.NEW, #0)) jump:nt foo; r4 = #10; } ");
   asm("{ if(cmp.eq(r5.NEW, #0)) jump:nt foo; r5 = #10; } ");*/
   asm(".byte 0x10\n"
       ".byte 0x40\n"
       ".byte 0xdd\n"
       ".byte 0x91\n"
       ".byte 0x61\n"
       ".byte 0x44\n"
       ".byte 0xe3\n"
       ".byte 0x0c\n"
       ".byte 0xad\n"
       ".byte 0xc0\n"
       ".byte 0x10\n"
       ".byte 0xad\n"
       );
   return 0;
}

int test_decomp() {
	int x = rand() * 100000;
	int y = 0;
	while(x != 1) {
		y += 1;
		if(x % 2 == 0) {
			x >>= 1;
		} else {
			x = (x * 3) + 1;
		}
	}
	return y;	
}

int main() {
	test_s3_new();
	
	test_decomp();
}
