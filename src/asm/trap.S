# trap.S
# In the future our trap vector will go here.

.global m_trap_vector
# This will be our trap vector when we start
# handling interrupts.
m_trap_vector:
	mret

