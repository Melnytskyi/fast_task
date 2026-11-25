; Copyright Danyil Melnytskyi 2022-Present
;
; Distributed under the Boost Software License, Version 1.0.
; (See accompanying file LICENSE or copy at
; http://www.boost.org/LICENSE_1_0.txt)

ifdef rsp
.code
;the thread_interrupter_asm_* functions could be called anywhere from code, it saves everything in the stack and calls interrupter
;
;Entry stack layout (set up by thread::insert_context):
;  [rsp +  0] = arg
;  [rsp +  8] = inserted_context
;  [rsp + 16] = original Rip (return address)
;
;Frame layout after prologue (mov rbp, rsp):
;  [rbp +   0] = r15
;  [rbp +   8] = r14
;  [rbp +  16] = r13
;  [rbp +  24] = r12
;  [rbp +  32] = r11
;  [rbp +  40] = r10
;  [rbp +  48] = r9
;  [rbp +  56] = r8
;  [rbp +  64] = rdi
;  [rbp +  72] = rsi
;  [rbp +  80] = rdx
;  [rbp +  88] = rcx
;  [rbp +  96] = rbx
;  [rbp + 104] = rax
;  [rbp + 112] = rflags
;  [rbp + 120] = saved rbp
;  [rbp + 128] = arg
;  [rbp + 136] = inserted_context
;  [rbp + 144] = original Rip

thread_interrupter_asm PROC FRAME
    ;inserted_context + arg (16 bytes) already pushed by insert_context
    .allocstack 16
    push rbp
    .pushreg rbp

    ;save flags
    pushfq
    .allocstack 8

    ;save registers
    push rax
    .pushreg rax
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    push rdx
    .pushreg rdx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .pushreg r8
    push r9
    .pushreg r9
    push r10
    .pushreg r10
    push r11
    .pushreg r11
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0h
    .endprolog

    ;save volatile xmm0-xmm5 (SSE2 is baseline on x86-64)
    sub rsp, 60h
    and rsp, 0fffffffffffffff0h
    movups [rsp], xmm0
    movups [rsp+10h], xmm1
    movups [rsp+20h], xmm2
    movups [rsp+30h], xmm3
    movups [rsp+40h], xmm4
    movups [rsp+50h], xmm5

    mov rax, [rbp + 136] ;get interrupter
    mov rcx, [rbp + 128] ;get args
    and rsp, 0fffffffffffffff0h
    ;make shadow space for Windows x64 ABI
    sub rsp, 20h
    cld
    ;call void interrupter(void*)
    call rax

    ;restore volatile xmm0-xmm5
    mov rsp, rbp
    sub rsp, 60h
    and rsp, 0fffffffffffffff0h
    movups xmm0, [rsp]
    movups xmm1, [rsp+10h]
    movups xmm2, [rsp+20h]
    movups xmm3, [rsp+30h]
    movups xmm4, [rsp+40h]
    movups xmm5, [rsp+50h]

    ;restore stack and reposition rbp/rflags so add rsp, 16 does not clobber flags
    mov rsp, rbp
    mov rax, [rbp + 112]
    mov [rbp + 136], rax
    mov rax, [rbp + 120]
    mov [rbp + 128], rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    pop rbp
    popfq
    ret
thread_interrupter_asm ENDP

thread_interrupter_asm_zmm PROC FRAME
    ;inserted_context + arg (16 bytes) already pushed by insert_context
    .allocstack 16
    push rbp
    .pushreg rbp

    ;save flags
    pushfq
    .allocstack 8

    ;save registers
    push rax
    .pushreg rax
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    push rdx
    .pushreg rdx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .pushreg r8
    push r9
    .pushreg r9
    push r10
    .pushreg r10
    push r11
    .pushreg r11
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0h
    .endprolog

    ;save zmm0-zmm31 (800h) + k0-k7 (40h) = 840h bytes, 64-byte aligned
    sub rsp, 840h
    and rsp, 0ffffffffffffffc0h
    vmovups [rsp], zmm0
    vmovups [rsp+40h], zmm1
    vmovups [rsp+80h], zmm2
    vmovups [rsp+0c0h], zmm3
    vmovups [rsp+100h], zmm4
    vmovups [rsp+140h], zmm5
    vmovups [rsp+180h], zmm6
    vmovups [rsp+1c0h], zmm7
    vmovups [rsp+200h], zmm8
    vmovups [rsp+240h], zmm9
    vmovups [rsp+280h], zmm10
    vmovups [rsp+2c0h], zmm11
    vmovups [rsp+300h], zmm12
    vmovups [rsp+340h], zmm13
    vmovups [rsp+380h], zmm14
    vmovups [rsp+3c0h], zmm15
    vmovups [rsp+400h], zmm16
    vmovups [rsp+440h], zmm17
    vmovups [rsp+480h], zmm18
    vmovups [rsp+4c0h], zmm19
    vmovups [rsp+500h], zmm20
    vmovups [rsp+540h], zmm21
    vmovups [rsp+580h], zmm22
    vmovups [rsp+5c0h], zmm23
    vmovups [rsp+600h], zmm24
    vmovups [rsp+640h], zmm25
    vmovups [rsp+680h], zmm26
    vmovups [rsp+6c0h], zmm27
    vmovups [rsp+700h], zmm28
    vmovups [rsp+740h], zmm29
    vmovups [rsp+780h], zmm30
    vmovups [rsp+7c0h], zmm31
    kmovq qword ptr [rsp+800h], k0
    kmovq qword ptr [rsp+808h], k1
    kmovq qword ptr [rsp+810h], k2
    kmovq qword ptr [rsp+818h], k3
    kmovq qword ptr [rsp+820h], k4
    kmovq qword ptr [rsp+828h], k5
    kmovq qword ptr [rsp+830h], k6
    kmovq qword ptr [rsp+838h], k7

    mov rax, [rbp + 136] ;get interrupter
    mov rcx, [rbp + 128] ;get args
    and rsp, 0fffffffffffffff0h
    ;make shadow space for Windows x64 ABI
    sub rsp, 20h
    cld
    ;call void interrupter(void*)
    call rax

    ;restore zmm0-zmm31 and k0-k7 from the exact saved base
    mov rsp, rbp
    sub rsp, 840h
    and rsp, 0ffffffffffffffc0h
    kmovq k0, qword ptr [rsp+800h]
    kmovq k1, qword ptr [rsp+808h]
    kmovq k2, qword ptr [rsp+810h]
    kmovq k3, qword ptr [rsp+818h]
    kmovq k4, qword ptr [rsp+820h]
    kmovq k5, qword ptr [rsp+828h]
    kmovq k6, qword ptr [rsp+830h]
    kmovq k7, qword ptr [rsp+838h]
    vmovups zmm0, [rsp]
    vmovups zmm1, [rsp+40h]
    vmovups zmm2, [rsp+80h]
    vmovups zmm3, [rsp+0c0h]
    vmovups zmm4, [rsp+100h]
    vmovups zmm5, [rsp+140h]
    vmovups zmm6, [rsp+180h]
    vmovups zmm7, [rsp+1c0h]
    vmovups zmm8, [rsp+200h]
    vmovups zmm9, [rsp+240h]
    vmovups zmm10, [rsp+280h]
    vmovups zmm11, [rsp+2c0h]
    vmovups zmm12, [rsp+300h]
    vmovups zmm13, [rsp+340h]
    vmovups zmm14, [rsp+380h]
    vmovups zmm15, [rsp+3c0h]
    vmovups zmm16, [rsp+400h]
    vmovups zmm17, [rsp+440h]
    vmovups zmm18, [rsp+480h]
    vmovups zmm19, [rsp+4c0h]
    vmovups zmm20, [rsp+500h]
    vmovups zmm21, [rsp+540h]
    vmovups zmm22, [rsp+580h]
    vmovups zmm23, [rsp+5c0h]
    vmovups zmm24, [rsp+600h]
    vmovups zmm25, [rsp+640h]
    vmovups zmm26, [rsp+680h]
    vmovups zmm27, [rsp+6c0h]
    vmovups zmm28, [rsp+700h]
    vmovups zmm29, [rsp+740h]
    vmovups zmm30, [rsp+780h]
    vmovups zmm31, [rsp+7c0h]

    mov rsp, rbp
    mov rax, [rbp + 112]
    mov [rbp + 136], rax
    mov rax, [rbp + 120]
    mov [rbp + 128], rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    pop rbp
    popfq
    ret
thread_interrupter_asm_zmm ENDP

thread_interrupter_asm_ymm PROC FRAME
    ;inserted_context + arg (16 bytes) already pushed by insert_context
    .allocstack 16
    push rbp
    .pushreg rbp

    ;save flags
    pushfq
    .allocstack 8

    ;save registers
    push rax
    .pushreg rax
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    push rdx
    .pushreg rdx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .pushreg r8
    push r9
    .pushreg r9
    push r10
    .pushreg r10
    push r11
    .pushreg r11
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0h
    .endprolog

    ;save ymm0-ymm15 (200h bytes), 32-byte aligned
    sub rsp, 200h
    and rsp, 0ffffffffffffffe0h
    vmovups [rsp], ymm0
    vmovups [rsp+20h], ymm1
    vmovups [rsp+40h], ymm2
    vmovups [rsp+60h], ymm3
    vmovups [rsp+80h], ymm4
    vmovups [rsp+0a0h], ymm5
    vmovups [rsp+0c0h], ymm6
    vmovups [rsp+0e0h], ymm7
    vmovups [rsp+100h], ymm8
    vmovups [rsp+120h], ymm9
    vmovups [rsp+140h], ymm10
    vmovups [rsp+160h], ymm11
    vmovups [rsp+180h], ymm12
    vmovups [rsp+1a0h], ymm13
    vmovups [rsp+1c0h], ymm14
    vmovups [rsp+1e0h], ymm15

    mov rax, [rbp + 136] ;get interrupter
    mov rcx, [rbp + 128] ;get args
    and rsp, 0fffffffffffffff0h
    ;make shadow space for Windows x64 ABI
    sub rsp, 20h
    cld
    ;call void interrupter(void*)
    call rax

    ;restore ymm0-ymm15 from the exact saved base
    mov rsp, rbp
    sub rsp, 200h
    and rsp, 0ffffffffffffffe0h
    vmovups ymm0, [rsp]
    vmovups ymm1, [rsp+20h]
    vmovups ymm2, [rsp+40h]
    vmovups ymm3, [rsp+60h]
    vmovups ymm4, [rsp+80h]
    vmovups ymm5, [rsp+0a0h]
    vmovups ymm6, [rsp+0c0h]
    vmovups ymm7, [rsp+0e0h]
    vmovups ymm8, [rsp+100h]
    vmovups ymm9, [rsp+120h]
    vmovups ymm10, [rsp+140h]
    vmovups ymm11, [rsp+160h]
    vmovups ymm12, [rsp+180h]
    vmovups ymm13, [rsp+1a0h]
    vmovups ymm14, [rsp+1c0h]
    vmovups ymm15, [rsp+1e0h]

    mov rsp, rbp
    mov rax, [rbp + 112]
    mov [rbp + 136], rax
    mov rax, [rbp + 120]
    mov [rbp + 128], rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    pop rbp
    popfq
    ret
thread_interrupter_asm_ymm ENDP

thread_interrupter_asm_xmm PROC FRAME
    ;inserted_context + arg (16 bytes) already pushed by insert_context
    .allocstack 16
    push rbp
    .pushreg rbp

    ;save flags
    pushfq
    .allocstack 8

    ;save registers
    push rax
    .pushreg rax
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    push rdx
    .pushreg rdx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .pushreg r8
    push r9
    .pushreg r9
    push r10
    .pushreg r10
    push r11
    .pushreg r11
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0h
    .endprolog

    ;save xmm0-xmm15 (100h bytes) using SSE2 movups, 16-byte aligned
    sub rsp, 100h
    and rsp, 0fffffffffffffff0h
    movups [rsp], xmm0
    movups [rsp+10h], xmm1
    movups [rsp+20h], xmm2
    movups [rsp+30h], xmm3
    movups [rsp+40h], xmm4
    movups [rsp+50h], xmm5
    movups [rsp+60h], xmm6
    movups [rsp+70h], xmm7
    movups [rsp+80h], xmm8
    movups [rsp+90h], xmm9
    movups [rsp+0a0h], xmm10
    movups [rsp+0b0h], xmm11
    movups [rsp+0c0h], xmm12
    movups [rsp+0d0h], xmm13
    movups [rsp+0e0h], xmm14
    movups [rsp+0f0h], xmm15

    mov rax, [rbp + 136] ;get interrupter
    mov rcx, [rbp + 128] ;get args
    and rsp, 0fffffffffffffff0h
    ;make shadow space for Windows x64 ABI
    sub rsp, 20h
    cld
    ;call void interrupter(void*)
    call rax

    ;restore xmm0-xmm15 from the exact saved base
    mov rsp, rbp
    sub rsp, 100h
    and rsp, 0fffffffffffffff0h
    movups xmm0, [rsp]
    movups xmm1, [rsp+10h]
    movups xmm2, [rsp+20h]
    movups xmm3, [rsp+30h]
    movups xmm4, [rsp+40h]
    movups xmm5, [rsp+50h]
    movups xmm6, [rsp+60h]
    movups xmm7, [rsp+70h]
    movups xmm8, [rsp+80h]
    movups xmm9, [rsp+90h]
    movups xmm10, [rsp+0a0h]
    movups xmm11, [rsp+0b0h]
    movups xmm12, [rsp+0c0h]
    movups xmm13, [rsp+0d0h]
    movups xmm14, [rsp+0e0h]
    movups xmm15, [rsp+0f0h]

    mov rsp, rbp
    mov rax, [rbp + 112]
    mov [rbp + 136], rax
    mov rax, [rbp + 120]
    mov [rbp + 128], rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    pop rbp
    popfq
    ret
thread_interrupter_asm_xmm ENDP

thread_interrupter_asm_xmm_small PROC FRAME
    ;inserted_context + arg (16 bytes) already pushed by insert_context
    .allocstack 16
    push rbp
    .pushreg rbp

    ;save flags
    pushfq
    .allocstack 8

    ;save registers
    push rax
    .pushreg rax
    push rbx
    .pushreg rbx
    push rcx
    .pushreg rcx
    push rdx
    .pushreg rdx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .pushreg r8
    push r9
    .pushreg r9
    push r10
    .pushreg r10
    push r11
    .pushreg r11
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0h
    .endprolog

    ;save xmm0-xmm7 (80h bytes) using SSE2 movups, 16-byte aligned
    sub rsp, 80h
    and rsp, 0fffffffffffffff0h
    movups [rsp], xmm0
    movups [rsp+10h], xmm1
    movups [rsp+20h], xmm2
    movups [rsp+30h], xmm3
    movups [rsp+40h], xmm4
    movups [rsp+50h], xmm5
    movups [rsp+60h], xmm6
    movups [rsp+70h], xmm7

    mov rax, [rbp + 136] ;get interrupter
    mov rcx, [rbp + 128] ;get args
    and rsp, 0fffffffffffffff0h
    ;make shadow space for Windows x64 ABI
    sub rsp, 20h
    cld
    ;call void interrupter(void*)
    call rax

    ;restore xmm0-xmm7 from the exact saved base
    mov rsp, rbp
    sub rsp, 80h
    and rsp, 0fffffffffffffff0h
    movups xmm0, [rsp]
    movups xmm1, [rsp+10h]
    movups xmm2, [rsp+20h]
    movups xmm3, [rsp+30h]
    movups xmm4, [rsp+40h]
    movups xmm5, [rsp+50h]
    movups xmm6, [rsp+60h]
    movups xmm7, [rsp+70h]

    mov rsp, rbp
    mov rax, [rbp + 112]
    mov [rbp + 136], rax
    mov rax, [rbp + 120]
    mov [rbp + 128], rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    pop rbp
    popfq
    ret
thread_interrupter_asm_xmm_small ENDP
endif
END
