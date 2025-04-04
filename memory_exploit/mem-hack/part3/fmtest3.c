// gcc -o fmtest3 fmtest3.c
#include <stdio.h>

char buffer[6] = "Hello";

int main() {
	printf("%71c%hhn", 'a', buffer);
	printf("\n[*] buffer : %s\n", buffer);
	return 0;
}
