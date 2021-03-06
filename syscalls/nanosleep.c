/*
 * SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp, struct timespec __user *, rmtp)
 */
#include "sanitise.h"

struct syscallentry syscall_nanosleep = {
	.name = "nanosleep",
	.num_args = 2,
	.arg1name = "rqtp",
	.arg1type = ARG_TIMESPEC,
	.arg2name = "rmtp",
	.arg2type = ARG_TIMESPEC,
	.flags = AVOID_SYSCALL, // Boring.  Can cause long sleeps.
};
