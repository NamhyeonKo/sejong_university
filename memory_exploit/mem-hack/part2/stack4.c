// gcc -o stack4 stack4.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win() {
	printf("Done!, code flow successfully changed\n");
}

int main(int argc, char **argv) {
	char buffer[64];
	gets(buffer);

	return 0;
}
