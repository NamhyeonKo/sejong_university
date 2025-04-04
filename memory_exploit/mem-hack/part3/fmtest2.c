// gcc -o fmtest2 fmtest2.c
#include <stdio.h>
int main() {
	printf("%d %d %d\n", 1, 2, 3);
	printf("%3$d %1$d %2$d\n", 1, 2, 3);
	return 0;
}
