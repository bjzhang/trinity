/*
 * SYSCALL_DEFINE2(settimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include "sanitise.h"

struct syscallentry syscall_settimeofday = {
	.name = "settimeofday",
	.num_args = 2,
	.arg1name = "tv",
	.arg1type = ARG_TIMEVAL,
	.arg2name = "tz",
	.arg2type = ARG_TIMEZONE,
};
