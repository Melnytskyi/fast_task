// Copyright Danyil Melnytskyi 2026-Present
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#if defined(__linux__) && defined(__x86_64__)

.text

// Entry stack layout set up by posix_signal_handler via ucontext_t:
//   [rsp + 0]          = original RIP (return address)
//   [rsp + 8 .. +135]  = 128-byte System V AMD64 Red Zone (untouched)
//   rsp + 136          = original RSP
//
// Each trampoline saves rflags, all 15 GPRs, and FPU/SIMD state, calls
// ft_linux_preempt_entry() in normal user space (outside signal context),
// restores everything, and executes `retq $128` to return to original RIP
// with RSP == original RSP and rflags untouched.

.macro PREEMPT_PROLOGUE
    .cfi_startproc simple
    .cfi_signal_frame
    .cfi_def_cfa %rsp, 136
    .cfi_offset %rip, -136

    pushfq
    .cfi_adjust_cfa_offset 8
    pushq %rax
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rax, 0
    pushq %rbx
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rbx, 0
    pushq %rcx
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rcx, 0
    pushq %rdx
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rdx, 0
    pushq %rsi
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rsi, 0
    pushq %rdi
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rdi, 0
    pushq %rbp
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %rbp, 0
    pushq %r8
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r8, 0
    pushq %r9
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r9, 0
    pushq %r10
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r10, 0
    pushq %r11
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r11, 0
    pushq %r12
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r12, 0
    pushq %r13
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r13, 0
    pushq %r14
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r14, 0
    pushq %r15
    .cfi_adjust_cfa_offset 8
    .cfi_rel_offset %r15, 0

    movq %rsp, %rbp
    .cfi_def_cfa_register %rbp
.endm

.macro PREEMPT_EPILOGUE
    movq %rbp, %rsp
    .cfi_def_cfa_register %rsp

    popq %r15
    .cfi_adjust_cfa_offset -8
    popq %r14
    .cfi_adjust_cfa_offset -8
    popq %r13
    .cfi_adjust_cfa_offset -8
    popq %r12
    .cfi_adjust_cfa_offset -8
    popq %r11
    .cfi_adjust_cfa_offset -8
    popq %r10
    .cfi_adjust_cfa_offset -8
    popq %r9
    .cfi_adjust_cfa_offset -8
    popq %r8
    .cfi_adjust_cfa_offset -8
    popq %rbp
    .cfi_adjust_cfa_offset -8
    popq %rdi
    .cfi_adjust_cfa_offset -8
    popq %rsi
    .cfi_adjust_cfa_offset -8
    popq %rdx
    .cfi_adjust_cfa_offset -8
    popq %rcx
    .cfi_adjust_cfa_offset -8
    popq %rbx
    .cfi_adjust_cfa_offset -8
    popq %rax
    .cfi_adjust_cfa_offset -8
    popfq
    .cfi_adjust_cfa_offset -8

    retq $128
    .cfi_endproc
.endm

// Baseline x86-64 SSE2 + x87 FPU (fxsave64/fxrstor64)
.globl ft_linux_preempt_trampoline_sse
.hidden ft_linux_preempt_trampoline_sse
.type ft_linux_preempt_trampoline_sse, @function
.p2align 4
ft_linux_preempt_trampoline_sse:
    PREEMPT_PROLOGUE

    subq $512, %rsp
    andq $-16, %rsp
    fxsave64 (%rsp)

    cld
    call ft_linux_preempt_entry

    movq %rbp, %rsp
    subq $512, %rsp
    andq $-16, %rsp
    fxrstor64 (%rsp)

    PREEMPT_EPILOGUE
.size ft_linux_preempt_trampoline_sse, .-ft_linux_preempt_trampoline_sse

// AVX (fxsave64 + ymm0-ymm15)
.globl ft_linux_preempt_trampoline_avx
.hidden ft_linux_preempt_trampoline_avx
.type ft_linux_preempt_trampoline_avx, @function
.p2align 4
ft_linux_preempt_trampoline_avx:
    PREEMPT_PROLOGUE

    // 512 bytes fxsave + 512 bytes ymm0-ymm15 = 1024 bytes, 32-byte aligned
    subq $1024, %rsp
    andq $-32, %rsp
    fxsave64 (%rsp)
    vmovdqu %ymm0,  512(%rsp)
    vmovdqu %ymm1,  544(%rsp)
    vmovdqu %ymm2,  576(%rsp)
    vmovdqu %ymm3,  608(%rsp)
    vmovdqu %ymm4,  640(%rsp)
    vmovdqu %ymm5,  672(%rsp)
    vmovdqu %ymm6,  704(%rsp)
    vmovdqu %ymm7,  736(%rsp)
    vmovdqu %ymm8,  768(%rsp)
    vmovdqu %ymm9,  800(%rsp)
    vmovdqu %ymm10, 832(%rsp)
    vmovdqu %ymm11, 864(%rsp)
    vmovdqu %ymm12, 896(%rsp)
    vmovdqu %ymm13, 928(%rsp)
    vmovdqu %ymm14, 960(%rsp)
    vmovdqu %ymm15, 992(%rsp)

    vzeroupper
    cld
    call ft_linux_preempt_entry

    movq %rbp, %rsp
    subq $1024, %rsp
    andq $-32, %rsp
    fxrstor64 (%rsp)
    vmovdqu 512(%rsp), %ymm0
    vmovdqu 544(%rsp), %ymm1
    vmovdqu 576(%rsp), %ymm2
    vmovdqu 608(%rsp), %ymm3
    vmovdqu 640(%rsp), %ymm4
    vmovdqu 672(%rsp), %ymm5
    vmovdqu 704(%rsp), %ymm6
    vmovdqu 736(%rsp), %ymm7
    vmovdqu 768(%rsp), %ymm8
    vmovdqu 800(%rsp), %ymm9
    vmovdqu 832(%rsp), %ymm10
    vmovdqu 864(%rsp), %ymm11
    vmovdqu 896(%rsp), %ymm12
    vmovdqu 928(%rsp), %ymm13
    vmovdqu 960(%rsp), %ymm14
    vmovdqu 992(%rsp), %ymm15

    PREEMPT_EPILOGUE
.size ft_linux_preempt_trampoline_avx, .-ft_linux_preempt_trampoline_avx

// AVX-512 (fxsave64 + zmm0-zmm31 + k0-k7)
.globl ft_linux_preempt_trampoline_avx512
.hidden ft_linux_preempt_trampoline_avx512
.type ft_linux_preempt_trampoline_avx512, @function
.p2align 4
ft_linux_preempt_trampoline_avx512:
    PREEMPT_PROLOGUE

    // 512 fxsave + 2048 zmm0-31 + 64 k0-7 = 2624 bytes, 64-byte aligned
    subq $2624, %rsp
    andq $-64, %rsp
    fxsave64 (%rsp)
    vmovdqu64 %zmm0,  512(%rsp)
    vmovdqu64 %zmm1,  576(%rsp)
    vmovdqu64 %zmm2,  640(%rsp)
    vmovdqu64 %zmm3,  704(%rsp)
    vmovdqu64 %zmm4,  768(%rsp)
    vmovdqu64 %zmm5,  832(%rsp)
    vmovdqu64 %zmm6,  896(%rsp)
    vmovdqu64 %zmm7,  960(%rsp)
    vmovdqu64 %zmm8,  1024(%rsp)
    vmovdqu64 %zmm9,  1088(%rsp)
    vmovdqu64 %zmm10, 1152(%rsp)
    vmovdqu64 %zmm11, 1216(%rsp)
    vmovdqu64 %zmm12, 1280(%rsp)
    vmovdqu64 %zmm13, 1344(%rsp)
    vmovdqu64 %zmm14, 1408(%rsp)
    vmovdqu64 %zmm15, 1472(%rsp)
    vmovdqu64 %zmm16, 1536(%rsp)
    vmovdqu64 %zmm17, 1600(%rsp)
    vmovdqu64 %zmm18, 1664(%rsp)
    vmovdqu64 %zmm19, 1728(%rsp)
    vmovdqu64 %zmm20, 1792(%rsp)
    vmovdqu64 %zmm21, 1856(%rsp)
    vmovdqu64 %zmm22, 1920(%rsp)
    vmovdqu64 %zmm23, 1984(%rsp)
    vmovdqu64 %zmm24, 2048(%rsp)
    vmovdqu64 %zmm25, 2112(%rsp)
    vmovdqu64 %zmm26, 2176(%rsp)
    vmovdqu64 %zmm27, 2240(%rsp)
    vmovdqu64 %zmm28, 2304(%rsp)
    vmovdqu64 %zmm29, 2368(%rsp)
    vmovdqu64 %zmm30, 2432(%rsp)
    vmovdqu64 %zmm31, 2496(%rsp)
    kmovq %k0, 2560(%rsp)
    kmovq %k1, 2568(%rsp)
    kmovq %k2, 2576(%rsp)
    kmovq %k3, 2584(%rsp)
    kmovq %k4, 2592(%rsp)
    kmovq %k5, 2600(%rsp)
    kmovq %k6, 2608(%rsp)
    kmovq %k7, 2616(%rsp)

    vzeroupper
    cld
    call ft_linux_preempt_entry

    movq %rbp, %rsp
    subq $2624, %rsp
    andq $-64, %rsp
    fxrstor64 (%rsp)
    kmovq 2560(%rsp), %k0
    kmovq 2568(%rsp), %k1
    kmovq 2576(%rsp), %k2
    kmovq 2584(%rsp), %k3
    kmovq 2592(%rsp), %k4
    kmovq 2600(%rsp), %k5
    kmovq 2608(%rsp), %k6
    kmovq 2616(%rsp), %k7
    vmovdqu64 512(%rsp),  %zmm0
    vmovdqu64 576(%rsp),  %zmm1
    vmovdqu64 640(%rsp),  %zmm2
    vmovdqu64 704(%rsp),  %zmm3
    vmovdqu64 768(%rsp),  %zmm4
    vmovdqu64 832(%rsp),  %zmm5
    vmovdqu64 896(%rsp),  %zmm6
    vmovdqu64 960(%rsp),  %zmm7
    vmovdqu64 1024(%rsp), %zmm8
    vmovdqu64 1088(%rsp), %zmm9
    vmovdqu64 1152(%rsp), %zmm10
    vmovdqu64 1216(%rsp), %zmm11
    vmovdqu64 1280(%rsp), %zmm12
    vmovdqu64 1344(%rsp), %zmm13
    vmovdqu64 1408(%rsp), %zmm14
    vmovdqu64 1472(%rsp), %zmm15
    vmovdqu64 1536(%rsp), %zmm16
    vmovdqu64 1600(%rsp), %zmm17
    vmovdqu64 1664(%rsp), %zmm18
    vmovdqu64 1728(%rsp), %zmm19
    vmovdqu64 1792(%rsp), %zmm20
    vmovdqu64 1856(%rsp), %zmm21
    vmovdqu64 1920(%rsp), %zmm22
    vmovdqu64 1984(%rsp), %zmm23
    vmovdqu64 2048(%rsp), %zmm24
    vmovdqu64 2112(%rsp), %zmm25
    vmovdqu64 2176(%rsp), %zmm26
    vmovdqu64 2240(%rsp), %zmm27
    vmovdqu64 2304(%rsp), %zmm28
    vmovdqu64 2368(%rsp), %zmm29
    vmovdqu64 2432(%rsp), %zmm30
    vmovdqu64 2496(%rsp), %zmm31

    PREEMPT_EPILOGUE
.size ft_linux_preempt_trampoline_avx512, .-ft_linux_preempt_trampoline_avx512

.section .note.GNU-stack,"",@progbits

#endif
