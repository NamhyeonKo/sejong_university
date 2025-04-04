// gcc -o test_myshellcode test_myshellcode.c -mpreferred-stack-boundary=4 -fno-stack-protector -z execstack -no-pie -fno-pic

int main() {
	char shellcode[] = "";
	((void(*)())shellcode)();
	return 0;
}
