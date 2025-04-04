// gcc -o helloworld helloworld.c -fno-stack-protector -no-pie -fno-pic 
#include <stdio.h>

int main(void) {
	printf("hello world!\n");
	return 0;
}
