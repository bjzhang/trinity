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

long JC_SyS_mq_timedreceive(mqd_t mqdes,
char __user *u_msg_ptr,
compat_size_t msg_len, unsigned int __user *u_msg_prio,
const struct compat_timespec __user *u_abs_timeout)
{
printk
("u_msg_prio<%u>, mqdes<%u>, msg_len<%u>, u_msg_ptr<%u>, u_abs_timeout<%u>",
u_msg_prio, mqdes, msg_len, u_msg_ptr, u_abs_timeout);
printk("parameter value:u_abs_timeout->tv_sec<%u>, u_abs_timeout->tv_nsec<%u>",
u_abs_timeout->tv_sec, u_abs_timeout->tv_nsec);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_mq_timedreceive,
.kp = {
.symbol_name    = "compat_sys_mq_timedreceive",
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
