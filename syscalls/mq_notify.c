/*
 * SYSCALL_DEFINE2(mq_notify, mqd_t, mqdes, const struct sigevent __user *, u_notification)
 */
#include "sanitise.h"

struct syscallentry syscall_mq_notify = {
	.name = "mq_notify",
	.num_args = 2,
	.arg1name = "mqdes",
	.arg1type = ARG_FD,
	.arg2name = "u_notification",
	.arg2type = ARG_SIGEVENT,
	.flags = NEED_ALARM,
};
