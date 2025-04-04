// sudo sysctl -w kernel.randomize_va_space=2
// gcc -o stack7 stack7.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
	char buffer[64];
	read(0, buffer, 0x300);
	write(1, buffer, strlen(buffer));
	return 0;
}
