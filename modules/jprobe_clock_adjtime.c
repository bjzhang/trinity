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

long JC_SyS_clock_adjtime(struct compat_timex *utp, int which_clock)
{
printk("parameter value:utp<%u>, which_clock<%u>", utp, which_clock);
printk
("utp->status<%u>, utp->stabil<%u>, utp->maxerror<%u>, utp->constant<%u>, utp->modes<%u>, utp->errcnt<%u>, utp->jitcnt<%u>, utp->shift<%u>, utp->calcnt<%u>, utp->stbcnt<%u>, utp->precision<%u>, utp->ppsfreq<%u>, utp->tai<%u>, utp->offset<%u>, utp->time.tv_sec<%u>, utp->time.tv_usec<%u>, utp->jitter<%u>, utp->freq<%u>, utp->tick<%u>, utp->tolerance<%u>, utp->esterror<%u>",
utp->status, utp->stabil, utp->maxerror, utp->constant, utp->modes,
utp->errcnt, utp->jitcnt, utp->shift, utp->calcnt, utp->stbcnt,
utp->precision, utp->ppsfreq, utp->tai, utp->offset,
utp->time.tv_sec, utp->time.tv_usec, utp->jitter, utp->freq,
utp->tick, utp->tolerance, utp->esterror);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_clock_adjtime,
.kp = {
.symbol_name    = "compat_sys_clock_adjtime",
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
