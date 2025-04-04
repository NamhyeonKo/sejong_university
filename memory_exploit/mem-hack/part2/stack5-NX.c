// gcc -o stack5-NX stack5-NX.c -mpreferred-stack-boundary=4 -fno-stack-protector -no-pie -fno-pic
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	char buffer[64];

	printf("Address of the buffer: %p\n", buffer);
	gets(buffer);
}

