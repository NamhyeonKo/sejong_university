// gcc -o SP2 SP2.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char *binsh = "/bin/sh";

void vuln(void) {
	char buffer[72];
	read(0, buffer, 81);
	printf("your buffer: %s\n", buffer);
}


int main(int argc, char **argv) {
	system("echo KMOOC-MEMHACK");
	vuln();

	return 0;
}
