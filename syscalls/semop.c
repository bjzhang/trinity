/*
 * SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops, unsigned, nsops)
 */
#include "sanitise.h"

struct syscallentry syscall_semop = {
	.name = "semop",
	.num_args = 3,
	.arg1name = "semid",
	.arg2name = "tsops",
	.arg2type = ARG_SEMBUF,
	.arg3name = "nsops",
};
