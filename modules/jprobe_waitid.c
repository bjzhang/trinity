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

long JC_SyS_waitid(int which, int pid, struct compat_siginfo *uinfo, int options, struct compat_rusage *uru)
{
printk("parameter value:which<%u>, pid<%u>, uinfo<%u>, options<%u>, uru<%u>", which, pid, uinfo, options, uru);
printk
("uru->ru_nvcsw<%u>, uru->ru_utime.tv_sec<%u>, uru->ru_utime.tv_usec<%u>, uru->ru_isrss<%u>, uru->ru_stime.tv_sec<%u>, uru->ru_stime.tv_usec<%u>, uru->ru_nsignals<%u>, uru->ru_nivcsw<%u>, uru->ru_idrss<%u>, uru->ru_msgsnd<%u>, uru->ru_ixrss<%u>, uru->ru_inblock<%u>, uru->ru_minflt<%u>, uru->ru_maxrss<%u>, uru->ru_msgrcv<%u>, uru->ru_nswap<%u>, uru->ru_oublock<%u>, uru->ru_majflt<%u>, uinfo->si_signo<%u>, uinfo->si_errno<%u>, uinfo->si_code<%u>, uinfo->_sifields._sigsys._call_addr<%u>, uinfo->_sifields._sigsys._arch<%u>, uinfo->_sifields._sigsys._syscall<%u>, uinfo->_sifields._timer._overrun<%u>, uinfo->_sifields._timer._sigval.sival_int<%u>, uinfo->_sifields._timer._sigval.sival_ptr<%u>, uinfo->_sifields._timer._sys_private<%u>, uinfo->_sifields._timer._tid<%u>, uinfo->_sifields._sigpoll._fd<%u>, uinfo->_sifields._sigpoll._band<%u>, uinfo->_sifields._kill._pid<%u>, uinfo->_sifields._kill._uid<%u>, uinfo->_sifields._pad[0]<%u>, uinfo->_sifields._pad[1]<%u>, uinfo->_sifields._pad[2]<%u>, uinfo->_sifields._pad[3]<%u>, uinfo->_sifields._pad[4]<%u>, uinfo->_sifields._pad[5]<%u>, uinfo->_sifields._pad[6]<%u>, uinfo->_sifields._pad[7]<%u>, uinfo->_sifields._pad[8]<%u>, uinfo->_sifields._pad[9]<%u>, uinfo->_sifields._pad[10]<%u>, uinfo->_sifields._pad[11]<%u>, uinfo->_sifields._pad[12]<%u>, uinfo->_sifields._pad[13]<%u>, uinfo->_sifields._pad[14]<%u>, uinfo->_sifields._pad[15]<%u>, uinfo->_sifields._pad[16]<%u>, uinfo->_sifields._pad[17]<%u>, uinfo->_sifields._pad[18]<%u>, uinfo->_sifields._pad[19]<%u>, uinfo->_sifields._pad[20]<%u>, uinfo->_sifields._pad[21]<%u>, uinfo->_sifields._pad[22]<%u>, uinfo->_sifields._pad[23]<%u>, uinfo->_sifields._pad[24]<%u>, uinfo->_sifields._pad[25]<%u>, uinfo->_sifields._pad[26]<%u>, uinfo->_sifields._pad[27]<%u>, uinfo->_sifields._pad[28]<%u>, uinfo->_sifields._sigchld._pid<%u>, uinfo->_sifields._sigchld._status<%u>, uinfo->_sifields._sigchld._uid<%u>, uinfo->_sifields._sigchld._utime<%u>, uinfo->_sifields._sigchld._stime<%u>, uinfo->_sifields._rt._pid<%u>, uinfo->_sifields._rt._uid<%u>, uinfo->_sifields._rt._sigval.sival_int<%u>, uinfo->_sifields._rt._sigval.sival_ptr<%u>, uinfo->_sifields._sigfault._addr<%u>, uinfo->_sifields._sigfault._addr_lsb<%u>",
uru->ru_nvcsw, uru->ru_utime.tv_sec, uru->ru_utime.tv_usec,
uru->ru_isrss, uru->ru_stime.tv_sec, uru->ru_stime.tv_usec,
uru->ru_nsignals, uru->ru_nivcsw, uru->ru_idrss, uru->ru_msgsnd,
uru->ru_ixrss, uru->ru_inblock, uru->ru_minflt, uru->ru_maxrss,
uru->ru_msgrcv, uru->ru_nswap, uru->ru_oublock, uru->ru_majflt,
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
.entry                  = JC_SyS_waitid,
.kp = {
.symbol_name    = "compat_sys_waitid",
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
