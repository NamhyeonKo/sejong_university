// gcc -o stack-frame1 stack-frame1.c

#include <stdio.h>

int a(void) {
	b();
	c();
	return (0);
}

int b(void) {
	return (0);
}

int c(void) {
	return (0);
}

int main(void) {
	a();
	return (0);
}
