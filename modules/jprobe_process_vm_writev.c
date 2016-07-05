#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <uapi/linux/eventpoll.h>
#include <uapi/asm-generic/statfs.h>
#include <asm-generic/int-ll64.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/dirent.h>
#include <uapi/asm-generic/poll.h>
#include <net/compat.h>

long JC_SyS_process_vm_writev(compat_pid_t pid,
const struct compat_iovec __user *lvec,
compat_ulong_t liovcnt, const struct compat_iovec __user *rvec,
compat_ulong_t riovcnt, compat_ulong_t flags)
{
printk
("riovcnt<%u>, rvec<%u>, pid<%u>, liovcnt<%u>, flags<%u>, lvec<%u>",
riovcnt, rvec, pid, liovcnt, flags, lvec);
printk("parameter value:lvec->iov_len<%u>, lvec->iov_base<%u>,rvec->iov_len<%u>, rvec->iov_base<%u>,", lvec->iov_len,
lvec->iov_base, rvec->iov_len, rvec->iov_base);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_process_vm_writev,
.kp = {
.symbol_name    = "compat_sys_process_vm_writev",
},
};

static int __init jprobe_init(void)
{
        int ret;

        ret = register_jprobe(&my_jprobe);
        if (ret < 0) {
                printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
                return -1;
        }

        return 0;
}

static void __exit jprobe_exit(void)
{
        unregister_jprobe(&my_jprobe);
        printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
