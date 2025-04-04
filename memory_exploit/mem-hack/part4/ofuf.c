// gcc -o ofuf ofuf.c
#include <stdio.h>
#include <limits.h>

int main() {
	printf("int overflow: %d\n", INT_MAX+1);
	printf("int underflow: %d\n", INT_MIN-1);

	printf("unsigned int overflow: %u\n", UINT_MAX+1);
	printf("unsigned int underflow: %u\n", 0-1);

	return 0;
}
