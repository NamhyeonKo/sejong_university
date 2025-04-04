// sudo sysctl -w kernel.randomize_va_space=2
// gcc -o stack6 stack6.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	char buffer[64];
	gets(buffer);
	puts(buffer);
	return 0;
}
