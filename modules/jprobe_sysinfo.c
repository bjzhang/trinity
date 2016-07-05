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

long JC_SyS_sysinfo(struct sysinfo *info)
{
printk("parameter value:info<%u>", info);
printk
("info->sharedram<%u>, info->uptime<%u>, info->freeram<%u>, info->freeswap<%u>, info->totalram<%u>, info->totalhigh<%u>, info->freehigh<%u>, info->pad<%u>, info->totalswap<%u>, info->_f[0]<%c>, info->_f[1]<%c>, info->_f[2]<%c>, info->_f[3]<%c>, info->_f[4]<%c>, info->_f[5]<%c>, info->_f[6]<%c>, info->_f[7]<%c>, info->loads[0]<%u>, info->loads[1]<%u>, info->loads[2]<%u>, info->mem_unit<%u>, info->procs<%u>, info->bufferram<%u>",
info->sharedram, info->uptime, info->freeram, info->freeswap,
info->totalram, info->totalhigh, info->freehigh, info->pad,
info->totalswap, info->_f[0], info->_f[1], info->_f[2],
info->_f[3], info->_f[4], info->_f[5], info->_f[6], info->_f[7],
info->loads[0], info->loads[1], info->loads[2], info->mem_unit,
info->procs, info->bufferram);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_sysinfo,
.kp = {
.symbol_name    = "compat_sys_sysinfo",
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
