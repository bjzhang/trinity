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
#include <linux/stat.h>
#include <linux/param.h>        /* for HZ */
#include <linux/sem.h>
#include <linux/socket.h>

struct compat_mq_attr {
        compat_long_t mq_flags;      /* message queue flags                  */
        compat_long_t mq_maxmsg;     /* maximum number of messages           */
        compat_long_t mq_msgsize;    /* maximum message size                 */
        compat_long_t mq_curmsgs;    /* number of messages currently queued  */
        compat_long_t __reserved[4]; /* ignored for input, zeroed for output */
};

long Jcompat_SyS_mq_open(const char __user *u_name,
int oflag, compat_mode_t mode,
struct compat_mq_attr __user *u_attr)
{
printk("parameter value:u_name<%u>, oflag<%u>, mode<%u>, u_attr<%u>", u_name, oflag, mode, u_attr);
printk("parameter value:u_attr->mq_flags<%u>, u_attr->mq_maxmsg<%u>, u_attr->mq_msgsize<%u>, u_attr->mq_curmsgs<%u>", u_attr->mq_flags, u_attr->mq_maxmsg, u_attr->mq_msgsize, u_attr->mq_curmsgs);
jprobe_return();        /* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = Jcompat_SyS_mq_open,
.kp = {
.symbol_name    = "compat_sys_mq_open",
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
