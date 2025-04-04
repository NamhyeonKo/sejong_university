//gcc -o stack2 stack2.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	volatile long id;
	char buffer[64];

	if(argc == 1) {
		errx(1, "please specify an argument\n");
	}

	id = 0;
	strcpy(buffer, argv[1]);

	if(id == 0x61646d696e) {
		printf("Done!\n");
	}
	else {
		printf("Try again, you got 0x%016lx\n", id);
	}

	return 0;
}
