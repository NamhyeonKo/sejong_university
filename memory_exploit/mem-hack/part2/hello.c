// gcc -o static-hello hello.c -static
// gcc -o dynamic-hello hello.c -no-pie

#include <stdio.h>

int main(void) {
	puts("hello world!");
	return 0;
}
