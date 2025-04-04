global _start

section .text

_start:
	mov rax, 0x0068732f6e69622f ;
	push rax ;

	mov rax, 0x3b ;
	mov rdx, 0x0  ;
	mov rsi, 0x0  ;
	mov rdi, rsp  ;
	syscall;
