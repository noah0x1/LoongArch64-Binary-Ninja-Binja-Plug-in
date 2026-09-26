#include "la64.h"

	.intel_syntax noprefix
	.text

	.globl	la_sext
	.hidden	la_sext
	.type	la_sext, @function
la_sext:
	mov	ecx, 64
	sub	ecx, esi
	mov	rax, rdi
	shl	rax, cl
	sar	rax, cl
	ret
	.size	la_sext, .-la_sext

	.globl	la_split21
	.hidden	la_split21
	.type	la_split21, @function
la_split21:
	mov	eax, edi
	and	eax, 0x1f
	shl	eax, 16
	mov	edx, edi
	shr	edx, 10
	and	edx, 0xffff
	or	eax, edx
	shl	rax, 43
	sar	rax, 43
	ret
	.size	la_split21, .-la_split21

	.globl	la_split26
	.hidden	la_split26
	.type	la_split26, @function
la_split26:
	mov	eax, edi
	and	eax, 0x3ff
	shl	eax, 16
	mov	edx, edi
	shr	edx, 10
	and	edx, 0xffff
	or	eax, edx
	shl	rax, 38
	sar	rax, 38
	ret
	.size	la_split26, .-la_split26

	.globl	la_lookup
	.hidden	la_lookup
	.type	la_lookup, @function
la_lookup:
	mov	eax, edi
	shr	eax, 20
	lea	rdx, [rip + la_bucket_start]
	mov	ecx, dword ptr [rdx + rax*4]
	mov	r8d, dword ptr [rdx + rax*4 + 4]
	mov	r9, qword ptr [rip + la_bucket_list]
	lea	r10, [rip + la_opcodes]
.Llk_loop:
	cmp	ecx, r8d
	jae	.Llk_none
	movzx	eax, word ptr [r9 + rcx*2]
	lea	r11, [rax + rax*2]
	mov	esi, edi
	and	esi, dword ptr [r10 + r11*8 + LA_OPC_MASK]
	cmp	esi, dword ptr [r10 + r11*8 + LA_OPC_MATCH]
	je	.Llk_found
	inc	ecx
	jmp	.Llk_loop
.Llk_found:
	ret
.Llk_none:
	mov	eax, -1
	ret
	.size	la_lookup, .-la_lookup

	.globl	la_extract
	.hidden	la_extract
	.type	la_extract, @function
la_extract:
	movzx	eax, byte ptr [rdx + LA_SPEC_KIND]
	cmp	eax, LA_K_SPLIT21
	je	.Lx_split21
	cmp	eax, LA_K_SPLIT26
	je	.Lx_split26

	mov	r8d, edi
	movzx	r9d, byte ptr [rdx + LA_SPEC_POS]
	movzx	r10d, byte ptr [rdx + LA_SPEC_WIDTH]
	mov	ecx, 64
	sub	ecx, r9d
	sub	ecx, r10d
	shl	r8, cl
	mov	ecx, 64
	sub	ecx, r10d
	test	eax, eax
	jnz	.Lx_signed
	shr	r8, cl
	jmp	.Lx_scale
.Lx_signed:
	sar	r8, cl
	jmp	.Lx_scale

.Lx_split21:
	mov	r8d, edi
	and	r8d, 0x1f
	shl	r8d, 16
	mov	eax, edi
	shr	eax, 10
	and	eax, 0xffff
	or	r8d, eax
	shl	r8, 43
	sar	r8, 43
	jmp	.Lx_scale

.Lx_split26:
	mov	r8d, edi
	and	r8d, 0x3ff
	shl	r8d, 16
	mov	eax, edi
	shr	eax, 10
	and	eax, 0xffff
	or	r8d, eax
	shl	r8, 38
	sar	r8, 38

.Lx_scale:
	movzx	ecx, byte ptr [rdx + LA_SPEC_SHIFT]
	shl	r8, cl
	movzx	eax, byte ptr [rdx + LA_SPEC_ADD]
	add	r8, rax
	cmp	byte ptr [rdx + LA_SPEC_PCREL], 0
	je	.Lx_done
	add	r8, rsi
.Lx_done:
	mov	rax, r8
	ret
	.size	la_extract, .-la_extract

	.globl	la_decode
	.hidden	la_decode
	.type	la_decode, @function
la_decode:
	cmp	rsi, 4
	jb	.Ld_short
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15
	mov	r12, rdx
	mov	r13, rcx
	mov	ebx, dword ptr [rdi]
	mov	edi, ebx
	call	la_lookup
	test	eax, eax
	js	.Ld_fail

	mov	qword ptr [r13 + LA_INSN_ADDR], r12
	mov	dword ptr [r13 + LA_INSN_WORD], ebx
	mov	word ptr [r13 + LA_INSN_INDEX], ax
	mov	r14, qword ptr [rip + la_info]
	lea	r14, [r14 + rax*LA_INFO_SIZE]
	movzx	eax, byte ptr [r14 + LA_INFO_NOPS]
	mov	byte ptr [r13 + LA_INSN_NOPS], al
	xor	r15d, r15d
.Ld_loop:
	movzx	eax, byte ptr [r14 + LA_INFO_NOPS]
	cmp	r15d, eax
	jae	.Ld_ok
	movzx	eax, byte ptr [r14 + r15 + LA_INFO_SPEC]
	lea	rdx, [rip + la_specs]
	lea	rdx, [rdx + rax*LA_SPEC_SIZE]
	mov	edi, ebx
	mov	rsi, r12
	call	la_extract
	mov	rcx, r15
	shl	rcx, 4
	mov	qword ptr [r13 + rcx + LA_INSN_OPS + LA_OPND_VALUE], rax
	movzx	eax, byte ptr [r14 + r15 + LA_INFO_SPEC]
	lea	rdx, [rip + la_specs]
	lea	rdx, [rdx + rax*LA_SPEC_SIZE]
	movzx	esi, byte ptr [rdx + LA_SPEC_TYPE]
	mov	byte ptr [r13 + rcx + LA_INSN_OPS + LA_OPND_TYPE], sil
	movzx	esi, byte ptr [rdx + LA_SPEC_SLOT]
	mov	byte ptr [r13 + rcx + LA_INSN_OPS + LA_OPND_SLOT], sil
	inc	r15d
	jmp	.Ld_loop
.Ld_ok:
	mov	eax, 1
	jmp	.Ld_out
.Ld_fail:
	xor	eax, eax
.Ld_out:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret
.Ld_short:
	xor	eax, eax
	ret
	.size	la_decode, .-la_decode

	.globl	la_pcrel
	.hidden	la_pcrel
	.type	la_pcrel, @function
la_pcrel:
	mov	rax, rsi
	test	edx, edx
	jz	.Lp_2
	cmp	edx, 2
	je	.Lp_18
	shl	rax, 12
	add	rax, rdi
	cmp	edx, 3
	jne	.Lp_done
	and	rax, -4096
.Lp_done:
	ret
.Lp_2:
	shl	rax, 2
	add	rax, rdi
	ret
.Lp_18:
	shl	rax, 18
	add	rax, rdi
	ret
	.size	la_pcrel, .-la_pcrel

	.section .note.GNU-stack,"",@progbits
