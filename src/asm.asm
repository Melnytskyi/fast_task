; Copyright Danyil Melnytskyi 2022-Present
;
; Distributed under the Boost Software License, Version 1.0.
; (See accompanying file LICENSE or copy at
; http://www.boost.org/LICENSE_1_0.txt)

ifdef rsp
.code
;the thread_interrupter_asm_* functions could be called anywhere from code, it saves everything in the stack and calls interrupter

thread_interrupter_asm PROC FRAME
    ;push interrupter
    ;push arg
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
	mov rbp,rsp
    .setframe rbp, 0h
	.endprolog





    
    mov rax, [rbp + 128];get interrupter
    mov rcx, [rbp + 120];get args
    and rsp, 0fffffffffffffff0h
    ;make buffer zone for c++
	sub rsp,20h
    ;call void interrupter()
    call rax
    ;restore stack
    mov rsp,rbp
    ;restore everything (flags + registers)
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    pop rbp
    ;pop interrupter and args
    lea rsp, [rsp+16]
    ret
thread_interrupter_asm ENDP
thread_interrupter_asm_zmm PROC FRAME
    ;push interrupter
    ;push arg
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
	mov rbp,rsp
    .setframe rbp, 0h
	.endprolog
    sub rsp, 800h
    and rsp, 0ffffffffffffffC0h
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



    mov rax, [rbp + 128];get interrupter
    mov rcx, [rbp + 120];get args
    and rsp, 0fffffffffffffff0h
    ;make buffer zone for c++
	sub rsp,20h
    ;call void interrupter()
    call rax
    ;restore stack
    mov rsp,rbp
    ;restore everything (flags + registers)
    and rsp, 0ffffffffffffffC0h

    vmovups zmm31, [rsp]
    vmovups zmm30, [rsp-40h]
    vmovups zmm29, [rsp-80h]
    vmovups zmm28, [rsp-0c0h]
    vmovups zmm27, [rsp-100h]
    vmovups zmm26, [rsp-140h]
    vmovups zmm25, [rsp-180h]
    vmovups zmm24, [rsp-1c0h]
    vmovups zmm23, [rsp-200h]
    vmovups zmm22, [rsp-240h]
    vmovups zmm21, [rsp-280h]
    vmovups zmm20, [rsp-2c0h]
    vmovups zmm19, [rsp-300h]
    vmovups zmm18, [rsp-340h]
    vmovups zmm17, [rsp-380h]
    vmovups zmm16, [rsp-3c0h]
    vmovups zmm15, [rsp-400h]
    vmovups zmm14, [rsp-440h]
    vmovups zmm13, [rsp-480h]
    vmovups zmm12, [rsp-4c0h]
    vmovups zmm11, [rsp-500h]
    vmovups zmm10, [rsp-540h]
    vmovups zmm9, [rsp-580h]
    vmovups zmm8, [rsp-5c0h]
    vmovups zmm7, [rsp-600h]
    vmovups zmm6, [rsp-640h]
    vmovups zmm5, [rsp-680h]
    vmovups zmm4, [rsp-6c0h]
    vmovups zmm3, [rsp-700h]
    vmovups zmm2, [rsp-740h]
    vmovups zmm1, [rsp-780h]
    vmovups zmm0, [rsp-7c0h]

    mov rsp,rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    pop rbp
    ;pop interrupter and args
    lea rsp, [rsp+16]
    ret
thread_interrupter_asm_zmm ENDP
thread_interrupter_asm_ymm PROC FRAME
    ;push interrupter
    ;push arg
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
	mov rbp,rsp
    .setframe rbp, 0h
	.endprolog

    sub rsp, 400h
    and rsp, 0ffffffffffffffe0h
    vmovups [rsp], ymm0
    vmovups [rsp+40h], ymm1
    vmovups [rsp+80h], ymm2
    vmovups [rsp+0c0h], ymm3
    vmovups [rsp+100h], ymm4
    vmovups [rsp+140h], ymm5
    vmovups [rsp+180h], ymm6
    vmovups [rsp+1c0h], ymm7
    vmovups [rsp+200h], ymm8
    vmovups [rsp+240h], ymm9
    vmovups [rsp+280h], ymm10
    vmovups [rsp+2c0h], ymm11
    vmovups [rsp+300h], ymm12
    vmovups [rsp+340h], ymm13
    vmovups [rsp+380h], ymm14
    vmovups [rsp+3c0h], ymm15

    





    mov rax, [rbp + 128];get interrupter
    mov rcx, [rbp + 120];get args
    and rsp, 0fffffffffffffff0h
    ;make buffer zone for c++
	sub rsp,20h
    ;call void interrupter()
    call rax
    ;restore stack
    mov rsp,rbp
    ;restore everything (flags + registers)
    and rsp, 0ffffffffffffffe0h

    vmovups ymm15, [rsp]
    vmovups ymm14, [rsp-40h]
    vmovups ymm13, [rsp-80h]
    vmovups ymm12, [rsp-0c0h]
    vmovups ymm11, [rsp-100h]
    vmovups ymm10, [rsp-140h]
    vmovups ymm9, [rsp-180h]
    vmovups ymm8, [rsp-1c0h]
    vmovups ymm7, [rsp-200h]
    vmovups ymm6, [rsp-240h]
    vmovups ymm5, [rsp-280h]
    vmovups ymm4, [rsp-2c0h]
    vmovups ymm3, [rsp-300h]
    vmovups ymm2, [rsp-340h]
    vmovups ymm1, [rsp-380h]
    vmovups ymm0, [rsp-3c0h]
    mov rsp,rbp
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    pop rbp
    ;pop interrupter and args
    lea rsp, [rsp+16]
    ret
thread_interrupter_asm_ymm ENDP
thread_interrupter_asm_xmm PROC FRAME
    ;push interrupter;136
    ;push arg        ;128
    .allocstack 16
    push rbp    ;120
	.pushreg rbp

    ;save flags
    pushfq       ;112
    .allocstack 8

    ;save registers
    push rax    ;104
	.pushreg rax
    push rbx    ;96
	.pushreg rbx
    push rcx    ;88
	.pushreg rcx
    push rdx    ;80
	.pushreg rdx
    push rdi    ;72
	.pushreg rdi
    push r8     ;64
	.pushreg r8
    push r9     ;56
	.pushreg r9
    push r10    ;48
	.pushreg r10
    push r11    ;40
	.pushreg r11
    push r12    ;32
	.pushreg r12
    push r13    ;24
	.pushreg r13
    push r14    ;16
	.pushreg r14
    push r15    ;8
	.pushreg r15
	mov rbp,rsp ;0
    .setframe rbp, 0h
	.endprolog

    sub rsp, 100h
    and rsp, 0fffffffffffffff0h
    vmovups [rsp], xmm0
    vmovups [rsp+10h], xmm1
    vmovups [rsp+20h], xmm2
    vmovups [rsp+30h], xmm3
    vmovups [rsp+40h], xmm4
    vmovups [rsp+50h], xmm5
    vmovups [rsp+60h], xmm6
    vmovups [rsp+70h], xmm7
    vmovups [rsp+80h], xmm8
    vmovups [rsp+90h], xmm9
    vmovups [rsp+0a0h], xmm10
    vmovups [rsp+0b0h], xmm11
    vmovups [rsp+0c0h], xmm12
    vmovups [rsp+0d0h], xmm13
    vmovups [rsp+0e0h], xmm14
    vmovups [rsp+0f0h], xmm15

    





    mov rax, [rbp + 128];get interrupter
    mov rcx, [rbp + 120];get args
    and rsp, 0fffffffffffffff0h
    ;make buffer zone for c++
	sub rsp,20h
    ;call void interrupter()
    call rax
    ;restore stack
    mov rsp,rbp
    ;restore everything (flags + registers)
    and rsp, 0fffffffffffffff0h

    vmovups xmm15, [rsp]
    vmovups xmm14, [rsp-10h]
    vmovups xmm13, [rsp-20h]
    vmovups xmm12, [rsp-30h]
    vmovups xmm11, [rsp-40h]
    vmovups xmm10, [rsp-50h]
    vmovups xmm9, [rsp-60h]
    vmovups xmm8, [rsp-70h]
    vmovups xmm7, [rsp-80h]
    vmovups xmm6, [rsp-90h]
    vmovups xmm5, [rsp-0a0h]
    vmovups xmm4, [rsp-0b0h]
    vmovups xmm3, [rsp-0c0h]
    vmovups xmm2, [rsp-0d0h]
    vmovups xmm1, [rsp-0e0h]
    vmovups xmm0, [rsp-0f0h]
    mov rsp,rbp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    pop rbp
    ;pop interrupter and args
    lea rsp, [rsp+16]
    ret
thread_interrupter_asm_xmm ENDP
thread_interrupter_asm_xmm_small PROC FRAME
    ;push interrupter
    ;push arg
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
	mov rbp,rsp
    .setframe rbp, 0h
	.endprolog

    sub rsp, 80h
    and rsp, 0fffffffffffffff0h
    vmovups [rsp], xmm0
    vmovups [rsp+10h], xmm1
    vmovups [rsp+20h], xmm2
    vmovups [rsp+30h], xmm3
    vmovups [rsp+40h], xmm4
    vmovups [rsp+50h], xmm5
    vmovups [rsp+60h], xmm6
    vmovups [rsp+70h], xmm7


    





    mov rax, [rbp + 128];get interrupter
    mov rcx, [rbp + 120];get args
    and rsp, 0fffffffffffffff0h
    ;make buffer zone for c++
	sub rsp,20h
    ;call void interrupter()
    call rax
    ;restore stack
    mov rsp,rbp
    ;restore everything (flags + registers)
    and rsp, 0fffffffffffffff0h

    vmovups xmm7, [rsp] 
    vmovups xmm6, [rsp-10h] 
    vmovups xmm5, [rsp-20h] 
    vmovups xmm4, [rsp-30h] 
    vmovups xmm3, [rsp-40h] 
    vmovups xmm2, [rsp-50h] 
    vmovups xmm1, [rsp-60h] 
    vmovups xmm0, [rsp-70h] 
    mov rsp,rbp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    pop rbp
    ;pop interrupter and args
    lea rsp, [rsp+16]
    ret
thread_interrupter_asm_xmm_small ENDP
endif
END
