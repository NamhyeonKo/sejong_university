// stack8.c
// sudo sysctl -w kernel.randomize_va_space=2
// gcc -o stack8 stack8.c -no-pie -fno-PIE
#include <stdio.h>
#include <stdlib.h>

void gadget(void) {
	__asm__ __volatile__("pop %rdx; ret");
}

int main(void) {
    char buffer[64];
    read(0, buffer, 0x100);
    printf("%s\n",buffer);
    read(0, buffer, 0x100);
    return 0;
}
