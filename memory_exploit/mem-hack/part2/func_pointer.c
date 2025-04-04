// gcc -o func_pointer func_pointer.c
#include <stdio.h>

int add(int a, int b) {
	return a + b;
}

int mul(int a, int b) {
	return a * b;
}

int main() {
	int (*operation)(int, int);
	
	operation = add;
	printf("10 + 5 = %d\n", operation(10, 5));

	operation = mul;
	printf("10 * 5 = %d\n", operation(10, 5));

	return 0;
}
