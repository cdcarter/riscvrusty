# trap.S
# In the future our trap vector will go here.

.altmacro
.set NUM_GP_REGS, 32  # Number of registers per context
.set NUM_FP_REGS, 32
.set REG_SIZE, 8   # Register size (in bytes)
.set MAX_CPUS, 8   # Maximum number of CPUs

# Use macros for saving and restoring multiple registers
.macro save_gp i, basereg=t6
	sd	x\i, ((\i)*REG_SIZE)(\basereg)
.endm
.macro load_gp i, basereg=t6
	ld	x\i, ((\i)*REG_SIZE)(\basereg)
.endm
.macro save_fp i, basereg=t6
	fsd	f\i, ((NUM_GP_REGS+(\i))*REG_SIZE)(\basereg)
.endm
.macro load_fp i, basereg=t6
	fld	f\i, ((NUM_GP_REGS+(\i))*REG_SIZE)(\basereg)
.endm


.global m_trap_vector
# This will be our trap vector when we start
# handling interrupts.
.option norvc
m_trap_vector:
	li x10, 0x1F
	csrw pmpcfg0, x10
	li x11, -1
	csrw pmpaddr0, x11
    # li s1, 0x10000000 # s1 := 0x1000_0000
    # li s2, 0x48       # s2 := 0x48
    # sb s2, 0(s1)      # (s1) := s2

# All registers are volatile here, we need to save them
# before we do anything.
	csrrw	t6, mscratch, t6
# csrrw will atomically swap t6 into mscratch and the old
# value of mscratch into t6. This is nice because we just
# switched values and didn't destroy anything -- all atomically!
# in cpu.rs we have a structure of:
#  32 gp regs		0
#  32 fp regs		256
#  SATP register	512
#  Trap stack       520
#  CPU HARTID		528
# We use t6 as the temporary register because it is the very
# bottom register (x31)
.set 	i, 1
.rept	30
	save_gp	%i
	.set	i, i+1
.endr

# Save the actual t6 register, which we swapped into
# mscratch
	mv		t5, t6
	csrr	t6, mscratch
	save_gp 31, t5

# Restore the kernel trap frame into mscratch
	csrw	mscratch, t5

# Get ready to go into Rust (trap.rs)
# We don't want to write into the user's stack or whomever
# messed with us here.
	csrr	a0, mepc
	csrr	a1, mtval
	csrr	a2, mcause
	csrr	a3, mhartid
	csrr	a4, mstatus
	mv		a5, t5
	ld		sp, 520(a5)
	call	m_trap

# When we get here, we've returned from m_trap, restore registers
# and return.
# m_trap will return the return address via a0.

	csrw	mepc, a0

# Now load the trap frame back into t6
	csrr	t6, mscratch

# Restore all GP registers
.set	i, 1
.rept	31
	load_gp %i
	.set	i, i+1
.endr

# Since we ran this loop 31 times starting with i = 1,
# the last one loaded t6 back to its original value.

	mret