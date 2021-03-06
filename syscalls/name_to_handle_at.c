/*
 *  SYSCALL_DEFINE5(name_to_handle_at, int, dfd, const char __user *, name,
 *	struct file_handle __user *, handle, int __user *, mnt_id,
 *	int, flag)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long name_to_handle_at_flags[] = {
	AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW,
	AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
};

struct syscallentry syscall_name_to_handle_at = {
	.name = "name_to_handle_at",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "name",
	.arg2type = ARG_ADDRESS,
	.arg3name = "handle",
	.arg3type = ARG_FILE_HANDLE,
	.arg4name = "mnt_id",
	.arg4type = ARG_ADDRESS,
	.arg5name = "flag",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(name_to_handle_at_flags),
	.flags = NEED_ALARM,
};
