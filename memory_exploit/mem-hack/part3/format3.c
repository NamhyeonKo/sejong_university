// gcc -o format3 format3.c -fno-stack-protector -no-pie -fno-pic
#include <stdlib.h>
#include <stdio.h>

int target;

void printbuffer(char *string) {
	printf(string);
}

void vuln() {
	char buffer[512];

	fgets(buffer, sizeof(buffer), stdin);

	printbuffer(buffer);

	if(target == 0x01025544) {
		printf("you have modified the target :)\n");
	} else {
		printf("target is %08x :(\n", target);
	}
}

int main(int argc, char **argv) {
	vuln();
}
