// gcc -o SP1 SP1.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>
#include <unistd.h>

char name[0x800];

void gadget(void) {
	__asm__ __volatile__("pop %rdx; ret");
}

int main(void) {
	char comment[0x20];

	setvbuf(stdout, 0, 2, 0);

	printf("name?: ");
	read(0, name, 0x800);
	printf("comment?: ");
	read(0, comment, 0x30);

	printf("thank you for your comment :)\n");

	return 0;
}

