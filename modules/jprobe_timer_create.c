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

long JC_SyS_timer_create(clockid_t which_clock,
struct compat_sigevent __user *timer_event_spec,
timer_t __user *created_timer_id)
{
printk
("timer_event_spec<%u>, created_timer_id<%u>, which_clock<%u>",
timer_event_spec, created_timer_id, which_clock);
printk
("timer_event_spec->_sigev_un._pad[0]<%u>, timer_event_spec->_sigev_un._pad[1]<%u>, timer_event_spec->_sigev_un._pad[2]<%u>, timer_event_spec->_sigev_un._pad[3]<%u>, timer_event_spec->_sigev_un._pad[4]<%u>, timer_event_spec->_sigev_un._pad[5]<%u>, timer_event_spec->_sigev_un._pad[6]<%u>, timer_event_spec->_sigev_un._pad[7]<%u>, timer_event_spec->_sigev_un._pad[8]<%u>, timer_event_spec->_sigev_un._pad[9]<%u>, timer_event_spec->_sigev_un._pad[10]<%u>, timer_event_spec->_sigev_un._pad[11]<%u>, timer_event_spec->_sigev_un._pad[12]<%u>, timer_event_spec->_sigev_un._tid<%u>, timer_event_spec->_sigev_un._sigev_thread._function<%u>, timer_event_spec->_sigev_un._sigev_thread._attribute<%u>, timer_event_spec->sigev_notify<%u>, timer_event_spec->sigev_signo<%u>, timer_event_spec->sigev_value.sival_int<%u>, timer_event_spec->sigev_value.sival_ptr<%u>",
timer_event_spec->_sigev_un._pad[0],
timer_event_spec->_sigev_un._pad[1],
timer_event_spec->_sigev_un._pad[2],
timer_event_spec->_sigev_un._pad[3],
timer_event_spec->_sigev_un._pad[4],
timer_event_spec->_sigev_un._pad[5],
timer_event_spec->_sigev_un._pad[6],
timer_event_spec->_sigev_un._pad[7],
timer_event_spec->_sigev_un._pad[8],
timer_event_spec->_sigev_un._pad[9],
timer_event_spec->_sigev_un._pad[10],
timer_event_spec->_sigev_un._pad[11],
timer_event_spec->_sigev_un._pad[12],
timer_event_spec->_sigev_un._tid,
timer_event_spec->_sigev_un._sigev_thread._function,
timer_event_spec->_sigev_un._sigev_thread._attribute,
timer_event_spec->sigev_notify, timer_event_spec->sigev_signo,
timer_event_spec->sigev_value.sival_int,
timer_event_spec->sigev_value.sival_ptr);
jprobe_return();	/* Always end with a call to jprobe_return(). */
return 0;
}

static struct jprobe my_jprobe = {
.entry                  = JC_SyS_timer_create,
.kp = {
.symbol_name    = "compat_sys_timer_create",
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
