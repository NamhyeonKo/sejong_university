// gcc -o format2 format2.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>
#include <stdlib.h>

int target;

void vuln() {
	char buffer[512];

	fgets(buffer, sizeof(buffer), stdin);
	printf(buffer);

	if(target == 64) {
		printf("you have modified the target :)\n");
	} else {
		printf("target is %d :(\n", target);
	}
}

int main(int argc, char **argv) {
	vuln();
}
