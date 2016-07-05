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

long JC_SyS_rt_sigtimedwait(compat_sigset_t __user *uthese,
struct compat_siginfo __user *uinfo,
struct compat_timespec __user *uts, compat_size_t sigsetsize)
{
printk("parameter value:uthese<%u>, sigsetsize<%u>, uinfo<%u>, uts<%u>", uthese,
sigsetsize, uinfo, uts);
printk
("uthese->sig[0]<%u>, uthese->sig[1]<%u>, uts->tv_sec<%u>, uts->tv_nsec<%u>, uinfo->si_signo<%u>, uinfo->si_errno<%u>, uinfo->si_code<%u>, uinfo->_sifields._sigsys._call_addr<%u>, uinfo->_sifields._sigsys._arch<%u>, uinfo->_sifields._sigsys._syscall<%u>, uinfo->_sifields._timer._overrun<%u>, uinfo->_sifields._timer._sigval.sival_int<%u>, uinfo->_sifields._timer._sigval.sival_ptr<%u>, uinfo->_sifields._timer._sys_private<%u>, uinfo->_sifields._timer._tid<%u>, uinfo->_sifields._sigpoll._fd<%u>, uinfo->_sifields._sigpoll._band<%u>, uinfo->_sifields._kill._pid<%u>, uinfo->_sifields._kill._uid<%u>, uinfo->_sifields._pad[0]<%u>, uinfo->_sifields._pad[1]<%u>, uinfo->_sifields._pad[2]<%u>, uinfo->_sifields._pad[3]<%u>, uinfo->_sifields._pad[4]<%u>, uinfo->_sifields._pad[5]<%u>, uinfo->_sifields._pad[6]<%u>, uinfo->_sifields._pad[7]<%u>, uinfo->_sifields._pad[8]<%u>, uinfo->_sifields._pad[9]<%u>, uinfo->_sifields._pad[10]<%u>, uinfo->_sifields._pad[11]<%u>, uinfo->_sifields._pad[12]<%u>, uinfo->_sifields._pad[13]<%u>, uinfo->_sifields._pad[14]<%u>, uinfo->_sifields._pad[15]<%u>, uinfo->_sifields._pad[16]<%u>, uinfo->_sifields._pad[17]<%u>, uinfo->_sifields._pad[18]<%u>, uinfo->_sifields._pad[19]<%u>, uinfo->_sifields._pad[20]<%u>, uinfo->_sifields._pad[21]<%u>, uinfo->_sifields._pad[22]<%u>, uinfo->_sifields._pad[23]<%u>, uinfo->_sifields._pad[24]<%u>, uinfo->_sifields._pad[25]<%u>, uinfo->_sifields._pad[26]<%u>, uinfo->_sifields._pad[27]<%u>, uinfo->_sifields._pad[28]<%u>, uinfo->_sifields._sigchld._pid<%u>, uinfo->_sifields._sigchld._status<%u>, uinfo->_sifields._sigchld._uid<%u>, uinfo->_sifields._sigchld._utime<%u>, uinfo->_sifields._sigchld._stime<%u>, uinfo->_sifields._rt._pid<%u>, uinfo->_sifields._rt._uid<%u>, uinfo->_sifields._rt._sigval.sival_int<%u>, uinfo->_sifields._rt._sigval.sival_ptr<%u>, uinfo->_sifields._sigfault._addr<%u>, uinfo->_sifields._sigfault._addr_lsb<%u>",
uthese->sig[0], uthese->sig[1], uts->tv_sec, uts->tv_nsec,
uinfo->si_signo, uinfo->si_errno, uinfo->si_code,
uinfo->_sifields._sigsys._call_addr,
uinfo->_sifields._sigsys._arch, uinfo->_sifields._sigsys._syscall,
uinfo->_sifields._timer._overrun,
uinfo->_sifields._timer._sigval.sival_int,
uinfo->_sifields._timer._sigval.sival_ptr,
uinfo->_sifields._timer._sys_private, uinfo->_sifields._timer._tid,
uinfo->_sifields._sigpoll._fd, uinfo->_sifields._sigpoll._band,
uinfo->_sifields._kill._pid, uinfo->_sifields._kill._uid,
uinfo->_sifields._pad[0], uinfo->_sifields._pad[1],
uinfo->_sifields._pad[2], uinfo->_sifields._pad[3],
uinfo->_sifields._pad[4], uinfo->_sifields._pad[5],
uinfo->_sifields._pad[6], uinfo->_sifields._pad[7],
uinfo->_sifields._pad[8], uinfo->_sifields._pad[9],
uinfo->_sifields._pad[10], uinfo->_sifields._pad[11],
uinfo->_sifields._pad[12], uinfo->_sifields._pad[13],
uinfo->_sifields._pad[14], uinfo->_sifields._pad[15],
uinfo->_sifields._pad[16], uinfo->_sifields._pad[17],
uinfo->_sifields._pad[18], uinfo->_sifields._pad[19],
uinfo->_sifields._pad[20], uinfo->_sifields._pad[21],
uinfo->_sifields._pad[22], uinfo->_sifields._pad[23],
uinfo->_sifields._pad[24], uinfo->_sifields._pad[25],
uinfo->_sifields._pad[26], uinfo->_sifields._pad[27],
uinfo->_sifields._pad[28], uinfo->_sifields._sigchld._pid,
uinfo->_sifields._sigchld._status, uinfo->_sifields._sigchld._uid,
uinfo->_sifields._sigchld._utime, uinfo->_sifields._sigchld._stime,
uinfo->_sifields._rt._pid, uinfo->_sifields._rt._uid,
uinfo->_sifields._rt._sigval.sival_int,
uinfo->_sifields._rt._sigval.sival_ptr,
uinfo->_sifields._sigfault._addr,
uinfo->_sifields._sigfault._addr_lsb);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_rt_sigtimedwait,
.kp = {
.symbol_name    = "compat_sys_rt_sigtimedwait",
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
