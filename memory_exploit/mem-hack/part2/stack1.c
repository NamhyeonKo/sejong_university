//gcc -o stack1 stack1.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
	volatile int modified;
	char buffer[64];
	
	modified = 0;

	gets(buffer);

	if(modified != 0)
		printf("Done!\n");
	else
		printf("Try again!\n");

	return 0;
}
