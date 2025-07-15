
extern void __putc(char c);

void putc(char c) {
   __putc(c); 
}

void puts(const char* foo) {
    int i = 0;
    while(foo[i] != 0) {
        putc(foo[i++]);
    }
}

int main() {
    puts("Hello, World\n");
    return 0;
}
