# Copyright (c) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

#  sidt_call (
#        OUT UINT64 addr
# )
.global sidt_call
sidt_call:
    sidt    (%rcx)
    ret


#  lidt_call (
#        IN UINT64 addr
# )
.global lidt_call
lidt_call:
    lidt    (%rcx)
    ret


.global read_cs_call
read_cs_call:
    mov   %cs, %rax
    ret

.global read_cr0_call
read_cr0_call:
    mov   %cr0, %rax
    ret

.global read_rflags_call
read_rflags_call:
    pushfq
    popq  %rax
    ret

.global read_cr4_call
read_cr4_call:
    mov   %cr4, %rax
    ret
