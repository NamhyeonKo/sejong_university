// gcc -o fmtest1 fmtest1.c
#include <stdio.h>

int main() {
	int val = 0x12345678;
	printf("%65c%n", 'a', &val);
	printf("val: %c %d\n", val, val);
	return 0;
}