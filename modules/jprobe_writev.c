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

long JC_SyS_writev(unsigned int fd, struct compat_iovec const *vec,
unsigned int vlen)
{
printk("parameter value:fd<%u>, vec<%u>, vlen<%u>", fd, vec, vlen);
printk("parameter value:vec->iov_len<%u>, vec->iov_base<%u>", vec->iov_len,
vec->iov_base);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_writev,
.kp = {
.symbol_name    = "compat_sys_writev",
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
