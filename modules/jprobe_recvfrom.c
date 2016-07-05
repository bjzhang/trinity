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

long JC_SyS_recvfrom(struct sockaddr *addr, unsigned int len, int *addrlen,
int fd, unsigned int flags, void *buf)
{
printk
("addr<%u>, len<%u>, addrlen<%u>, fd<%u>, flags<%u>, buf<%u>",
addr, len, addrlen, fd, flags, buf);
printk
("addr->sa_data[0]<%c>, addr->sa_data[1]<%c>, addr->sa_data[2]<%c>, addr->sa_data[3]<%c>, addr->sa_data[4]<%c>, addr->sa_data[5]<%c>, addr->sa_data[6]<%c>, addr->sa_data[7]<%c>, addr->sa_data[8]<%c>, addr->sa_data[9]<%c>, addr->sa_data[10]<%c>, addr->sa_data[11]<%c>, addr->sa_data[12]<%c>, addr->sa_data[13]<%c>, addr->sa_family<%u>",
addr->sa_data[0], addr->sa_data[1], addr->sa_data[2],
addr->sa_data[3], addr->sa_data[4], addr->sa_data[5],
addr->sa_data[6], addr->sa_data[7], addr->sa_data[8],
addr->sa_data[9], addr->sa_data[10], addr->sa_data[11],
addr->sa_data[12], addr->sa_data[13], addr->sa_family);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_recvfrom,
.kp = {
.symbol_name    = "compat_sys_recvfrom",
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
