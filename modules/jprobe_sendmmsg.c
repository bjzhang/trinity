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

long JC_SyS_sendmmsg(int fd, struct compat_mmsghdr __user *mmsg,
unsigned vlen, unsigned int flags)
{
printk("parameter value:mmsg<%u>, fd<%u>, flags<%u>, vlen<%u>", mmsg, fd, flags,
vlen);
printk
("mmsg->msg_hdr.msg_namelen<%u>, mmsg->msg_hdr.msg_iov<%u>, mmsg->msg_hdr.msg_iovlen<%u>, mmsg->msg_hdr.msg_name<%u>, mmsg->msg_hdr.msg_controllen<%u>, mmsg->msg_hdr.msg_control<%u>, mmsg->msg_hdr.msg_flags<%u>, mmsg->msg_len<%u>",
mmsg->msg_hdr.msg_namelen, mmsg->msg_hdr.msg_iov,
mmsg->msg_hdr.msg_iovlen, mmsg->msg_hdr.msg_name,
mmsg->msg_hdr.msg_controllen, mmsg->msg_hdr.msg_control,
mmsg->msg_hdr.msg_flags, mmsg->msg_len);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_sendmmsg,
.kp = {
.symbol_name    = "compat_sys_sendmmsg",
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
