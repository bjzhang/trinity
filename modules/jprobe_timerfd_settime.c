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

long JC_SyS_timerfd_settime(int ufd, int flags,
const struct compat_itimerspec __user *utmr,
struct compat_itimerspec __user *otmr)
{
printk("parameter value:flags<%u>, utmr<%u>, otmr<%u>, ufd<%u>", flags, utmr, otmr,
ufd);

printk
("utmr->it_interval.tv_sec<%u>, utmr->it_interval.tv_nsec<%u>, utmr->it_value.tv_sec<%u>, utmr->it_value.tv_nsec<%u>",
utmr->it_interval.tv_sec, utmr->it_interval.tv_nsec,
utmr->it_value.tv_sec, utmr->it_value.tv_nsec);

printk
("otmr->it_interval.tv_sec<%u>, otmr->it_interval.tv_nsec<%u>, otmr->it_value.tv_sec<%u>, otmr->it_value.tv_nsec<%u>",
otmr->it_interval.tv_sec, otmr->it_interval.tv_nsec,
otmr->it_value.tv_sec, otmr->it_value.tv_nsec);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_timerfd_settime,
.kp = {
.symbol_name    = "compat_sys_timerfd_settime",
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
