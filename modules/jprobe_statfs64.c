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

long JC_SyS_statfs64(const char __user *pathname, compat_size_t sz, struct compat_statfs64 __user *buf)
{
printk("parameter value:pathname<%s>, sz<%u>, buf<%u>", sz, pathname, buf);
printk
("buf->f_bsize<%u>, buf->f_bavail<%u>, buf->f_fsid.val[0]<%u>, buf->f_fsid.val[1]<%u>, buf->f_files<%u>, buf->f_frsize<%u>, buf->f_namelen<%u>, buf->f_blocks<%u>, buf->f_type<%u>, buf->f_ffree<%u>, buf->f_spare[0]<%u>, buf->f_spare[1]<%u>, buf->f_spare[2]<%u>, buf->f_spare[3]<%u>, buf->f_bfree<%u>, buf->f_flags<%u>",
buf->f_bsize, buf->f_bavail, buf->f_fsid.val[0],
buf->f_fsid.val[1], buf->f_files, buf->f_frsize, buf->f_namelen,
buf->f_blocks, buf->f_type, buf->f_ffree, buf->f_spare[0],
buf->f_spare[1], buf->f_spare[2], buf->f_spare[3], buf->f_bfree,
buf->f_flags);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_statfs64,
.kp = {
.symbol_name    = "compat_sys_statfs64",
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
