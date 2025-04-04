// gcc -o pivot pivot.c -fno-stack-protector -no-pie -fno-pic
#include <stdio.h>

void func(void) {
	char name[10] = "func";
	printf("%s\n",name);
}

int main(void) {
	char name[10] = "main";
	printf("%s\n",name);
	func();
	return 0;
}
