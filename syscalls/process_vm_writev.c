/*
 * SYSCALL_DEFINE6(process_vm_writev, pid_t, pid, const struct iovec __user *, lvec,
 *                unsigned long, liovcnt, const struct iovec __user *, rvec,
 *                unsigned long, riovcnt, unsigned long, flags)
 */
#include "sanitise.h"

static unsigned long process_vm_writev_flags[] = {
	0,	// currently no flags defined, mbz
};

struct syscallentry syscall_process_vm_writev = {
	.name = "process_vm_writev",
	.num_args = 6,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "lvec",
	.arg2type = ARG_STRUCT_IOVEC,
	.arg3name = "liovcnt",
	.arg3type = ARG_IOVECLEN,
	.arg4name = "rvec",
	.arg4type = ARG_STRUCT_IOVEC,
	.arg5name = "riovcnt",
	.arg5type = ARG_IOVECLEN,
	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = ARGLIST(process_vm_writev_flags),
};
