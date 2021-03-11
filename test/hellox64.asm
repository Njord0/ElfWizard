section .text
    global _start

_start:
    xor    rax,rax
    push   rax
    mov    eax, 0xa646c72
    push   rax
    movabs rax, 0x6f77206f6c6c6548
    push   rax
    mov    eax,0x1
    mov    edi,0x1
    mov    rsi,rsp
    mov    edx,0xd
    syscall 