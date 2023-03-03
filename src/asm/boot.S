# boot.S
# bootloader for SoS
# Stephen Marz
# 8 February 2019
.option norvc
.section .data

.section .text.init
.global _start
_start:
	# Any hardware threads (hart) that are not bootstrapping
	# need to wait for an IPI
	csrr	t0, mhartid
	bnez	t0, 3f
	# SATP should be zero, but let's make sure
	csrw	satp, zero
.option push
.option norelax
	la		gp, _global_pointer
.option pop

3:
	wfi
	j	3b
