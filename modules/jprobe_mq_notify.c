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

long JC_SyS_mq_notify(int mqdes, struct compat_sigevent const *u_notification)
{
printk("parameter value:mqdes<%u>, u_notification<%u>", mqdes, u_notification);
printk
("u_notification->_sigev_un._pad[0]<%u>, u_notification->_sigev_un._pad[1]<%u>, u_notification->_sigev_un._pad[2]<%u>, u_notification->_sigev_un._pad[3]<%u>, u_notification->_sigev_un._pad[4]<%u>, u_notification->_sigev_un._pad[5]<%u>, u_notification->_sigev_un._pad[6]<%u>, u_notification->_sigev_un._pad[7]<%u>, u_notification->_sigev_un._pad[8]<%u>, u_notification->_sigev_un._pad[9]<%u>, u_notification->_sigev_un._pad[10]<%u>, u_notification->_sigev_un._pad[11]<%u>, u_notification->_sigev_un._pad[12]<%u>, u_notification->_sigev_un._tid<%u>, u_notification->_sigev_un._sigev_thread._function<%u>, u_notification->_sigev_un._sigev_thread._attribute<%u>, u_notification->sigev_notify<%u>, u_notification->sigev_signo<%u>, u_notification->sigev_value.sival_int<%u>, u_notification->sigev_value.sival_ptr<%u>",
u_notification->_sigev_un._pad[0],
u_notification->_sigev_un._pad[1],
u_notification->_sigev_un._pad[2],
u_notification->_sigev_un._pad[3],
u_notification->_sigev_un._pad[4],
u_notification->_sigev_un._pad[5],
u_notification->_sigev_un._pad[6],
u_notification->_sigev_un._pad[7],
u_notification->_sigev_un._pad[8],
u_notification->_sigev_un._pad[9],
u_notification->_sigev_un._pad[10],
u_notification->_sigev_un._pad[11],
u_notification->_sigev_un._pad[12], u_notification->_sigev_un._tid,
u_notification->_sigev_un._sigev_thread._function,
u_notification->_sigev_un._sigev_thread._attribute,
u_notification->sigev_notify, u_notification->sigev_signo,
u_notification->sigev_value.sival_int,
u_notification->sigev_value.sival_ptr);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_mq_notify,
.kp = {
.symbol_name    = "compat_sys_mq_notify",
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
