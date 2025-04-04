// gcc -o stack-frame2 stack-frame2.c

#include <stdio.h>

int add(int a, int b) {
	int result = a + b;
	
	return result;
}

int main() {
	int x = 3;
	int y = 5;
	int sum = add(x, y);
	
	printf("Sum: %d\n", sum);

	return 0;
}
