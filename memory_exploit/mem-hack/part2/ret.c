// gcc -o ret ret.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic
#include <stdio.h>

void func() {
	printf("func function!\n");
}

int main(int argc, char **argv) {
	func();
	return 0;
}
