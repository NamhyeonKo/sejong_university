// gcc -o logic1 logic1.c
#include <stdio.h>

int main() {
	char buf[0x10] = "AAAAAAAAAAAAAAAA";
	char buf2[0x10] = "BBBBBBBBBBBBBBBB";

	printf("%s\n", buf);
	
	return 0;
}
