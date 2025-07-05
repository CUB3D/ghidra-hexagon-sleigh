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
   asm("{ if(cmp.eq(r28.NEW, #0)) jump:nt foo; r28 = #10; } ");
   /*asm("{ if(cmp.eq(r1.NEW, #0)) jump:nt foo; r1 = #10; } ");
   asm("{ if(cmp.eq(r2.NEW, #0)) jump:nt foo; r2 = #10; } ");
   asm("{ if(cmp.eq(r3.NEW, #0)) jump:nt foo; r3 = #10; } ");
   asm("{ if(cmp.eq(r4.NEW, #0)) jump:nt foo; r4 = #10; } ");
   asm("{ if(cmp.eq(r5.NEW, #0)) jump:nt foo; r5 = #10; } ");*/
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
