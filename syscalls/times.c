/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
#include "sanitise.h"

struct syscallentry syscall_times = {
	.name = "times",
	.num_args = 1,
	.arg1name = "tbuf",
	.arg1type = ARG_TMS,
};
