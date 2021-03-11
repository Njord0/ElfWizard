section .text
    global _start

_start:
    xor eax, eax
    push   eax
    push   0xa646c72
    push   0x6f77206f
    push   0x6c6c6548
    mov    ecx,esp
    mov    eax,0x4
    mov    ebx,0x1
    mov    edx,0xc
    int    0x80 
