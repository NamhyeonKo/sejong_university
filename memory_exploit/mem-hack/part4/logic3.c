// gcc -o logic3 logic3.c
#include <stdio.h>

int main() {
	int A = 0xf0000010;
	int B = 0x10000010;

	printf("%d\n", A+B);
	return 0;
}
