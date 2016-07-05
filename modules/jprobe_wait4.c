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

long JC_SyS_wait4(compat_pid_t pid,
compat_uint_t __user *stat_addr, int options,
struct compat_rusage __user *ru)
{
printk("parameter value:stat_addr<%u>, pid<%u>, options<%u>, ru<%u>", stat_addr,
pid, options, ru);
printk
("ru->ru_nvcsw<%u>, ru->ru_utime.tv_sec<%u>, ru->ru_utime.tv_usec<%u>, ru->ru_isrss<%u>, ru->ru_stime.tv_sec<%u>, ru->ru_stime.tv_usec<%u>, ru->ru_nsignals<%u>, ru->ru_nivcsw<%u>, ru->ru_idrss<%u>, ru->ru_msgsnd<%u>, ru->ru_ixrss<%u>, ru->ru_inblock<%u>, ru->ru_minflt<%u>, ru->ru_maxrss<%u>, ru->ru_msgrcv<%u>, ru->ru_nswap<%u>, ru->ru_oublock<%u>, ru->ru_majflt<%u>",
ru->ru_nvcsw, ru->ru_utime.tv_sec, ru->ru_utime.tv_usec,
ru->ru_isrss, ru->ru_stime.tv_sec, ru->ru_stime.tv_usec,
ru->ru_nsignals, ru->ru_nivcsw, ru->ru_idrss, ru->ru_msgsnd,
ru->ru_ixrss, ru->ru_inblock, ru->ru_minflt, ru->ru_maxrss,
ru->ru_msgrcv, ru->ru_nswap, ru->ru_oublock, ru->ru_majflt);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_wait4,
.kp = {
.symbol_name    = "compat_sys_wait4",
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
