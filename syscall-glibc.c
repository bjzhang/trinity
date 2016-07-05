#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "syscall.h"
#include <unistd.h>
//#include "syscall-glibc.h"

#include <unistd.h>
//#include <sys/memfd.h> 
#include <linux/random.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
//#include <linux/signal.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/kcmp.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
//#include <numaif.h>
//#include <keyutils.h> 
#include <mqueue.h>
#include <sys/types.h>
//#include <linux/getcpu.h> 
#include <linux/kexec.h>
#include <linux/futex.h>
#include <sys/types.h>
#include <syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <linux/unistd.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <linux/aio_abi.h>
#include <sys/epoll.h>

extern const char* ar_syscall_name[];

#define MODCMD_SIZE 100

int call_glibc_syscalls(int call, struct syscallrecord *rec)
{
	int ret = -1;
	char insmod_cmd[MODCMD_SIZE];
        char rmmod_cmd[MODCMD_SIZE];

	sprintf(insmod_cmd, "/sbin/insmod /tmp/modules/jprobe_%s*.ko", ar_syscall_name[call]);
	sprintf(rmmod_cmd, "/sbin/rmmod jprobe_%s", ar_syscall_name[call]);

	if(system(insmod_cmd) < 0) {
                printf("insmod error\n");
        }

	printf("call:%d\n", call);

	switch(call) {
//		case 0: ret = io_setup(rec->a1, rec->a2); break;
		case 0: ret = syscall(call, rec->a1, rec->a2); break;
//		case 1: ret = io_destroy(rec->a1); break;
		case 1: ret = syscall(call, rec->a1); break;
//		case 2: ret = io_submit(rec->a1, rec->a2, rec->a3); break;
		case 2: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 3: ret = io_cancel(rec->a1, rec->a2, rec->a3); break;
		case 3: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 4: ret = io_getevents(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 4: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 5: ret = setxattr(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 6: ret = lsetxattr(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 7: ret = fsetxattr(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 8: ret = getxattr(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 9: ret = lgetxattr(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 10: ret = fgetxattr(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 11: ret = listxattr(rec->a1, rec->a2, rec->a3); break;
		case 12: ret = llistxattr(rec->a1, rec->a2, rec->a3); break;
		case 13: ret = flistxattr(rec->a1, rec->a2, rec->a3); break;
		case 14: ret = removexattr(rec->a1, rec->a2); break;
		case 15: ret = lremovexattr(rec->a1, rec->a2); break;
		case 16: ret = fremovexattr(rec->a1, rec->a2); break;
		case 17: ret = getcwd(rec->a1, rec->a2); break;
//		case 18: ret = lookup_dcookie(rec->a1, rec->a2, rec->a3); break;
		case 18: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 19: ret = eventfd(rec->a1, rec->a2); break;
//		case 19: ret = syscall(call, rec->a1, rec->a2); break;
		case 20: ret = epoll_create1(rec->a1); break;
		case 21: ret = epoll_ctl(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 22: ret = epoll_pwait(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 23: ret = dup(rec->a1); break;
		case 24: ret = dup3(rec->a1, rec->a2, rec->a3); break;
		case 25: ret = fcntl(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 26: ret = inotify_init1(rec->a1); break;
		case 27: ret = inotify_add_watch(rec->a1, rec->a2, rec->a3); break;
		case 28: ret = inotify_rm_watch(rec->a1, rec->a2); break;
		case 29: ret = ioctl(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 30: ret = ioprio_set(rec->a1, rec->a2, rec->a3); break;
		case 30: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 31: ret = ioprio_get(rec->a1, rec->a2); break;
		case 31: ret = syscall(call, rec->a1, rec->a2); break;
		case 32: ret = flock(rec->a1, rec->a2); break;
		case 33: ret = mknodat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 34: ret = mkdirat(rec->a1, rec->a2, rec->a3); break;
		case 35: ret = unlinkat(rec->a1, rec->a2, rec->a3); break;
		case 36: ret = symlinkat(rec->a1, rec->a2, rec->a3); break;
		case 37: ret = linkat(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 38: ret = renameat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 39: ret = umount2(rec->a1, rec->a2); break;
		case 40: ret = mount(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 41: ret = pivot_root(rec->a1, rec->a2); break;
//		case 42: ret = ni_syscall(); break;
		case 42: ret = syscall(call); break;
		case 43: ret = statfs(rec->a1, rec->a2); break;
		case 44: ret = fstatfs(rec->a1, rec->a2); break;
		case 45: ret = truncate(rec->a1, rec->a2); break;
		case 46: ret = ftruncate(rec->a1, rec->a2); break;
		case 47: ret = fallocate(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 48: ret = faccessat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 49: ret = chdir(rec->a1); break;
		case 50: ret = fchdir(rec->a1); break;
		case 51: ret = chroot(rec->a1); break;
		case 52: ret = fchmod(rec->a1, rec->a2); break;
		case 53: ret = fchmodat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 54: ret = fchownat(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 55: ret = fchown(rec->a1, rec->a2, rec->a3); break;
		case 56: ret = openat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 57: ret = close(rec->a1); break;
		case 58: ret = vhangup(); break;
		case 59: ret = pipe2(rec->a1, rec->a2); break;
		case 60: ret = quotactl(rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 61: ret = getdents64(rec->a1, rec->a2, rec->a3); break;
		case 61: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 62: ret = lseek(rec->a1, rec->a2, rec->a3); break;
		case 63: ret = read(rec->a1, rec->a2, rec->a3); break;
		case 64: ret = write(rec->a1, rec->a2, rec->a3); break;
		case 65: ret = readv(rec->a1, rec->a2, rec->a3); break;
		case 66: ret = writev(rec->a1, rec->a2, rec->a3); break;
		case 67: ret = pread64(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 68: ret = pwrite64(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 69: ret = preadv(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 70: ret = pwritev(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 71: ret = sendfile64(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 72: ret = pselect(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 72: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 73: ret = ppoll(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 74: ret = signalfd(rec->a1, rec->a2, rec->a3); break;
//		case 74: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 75: ret = vmsplice(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 76: ret = splice(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 77: ret = tee(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 78: ret = readlinkat(rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 79: ret = newfstatat(); break;
		case 79: ret = syscall(call); break;
//		case 80: ret = newfstat(); break;
		case 80: ret = syscall(call); break;
		case 81: sync(); break;
		case 82: ret = fsync(rec->a1); break;
		case 83: ret = fdatasync(rec->a1); break;
		case 84: ret = sync_file_range(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 85: ret = timerfd_create(rec->a1, rec->a2); break;
		case 86: ret = timerfd_settime(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 87: ret = timerfd_gettime(rec->a1, rec->a2); break;
		case 88: ret = utimensat(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 89: ret = acct(rec->a1); break;
		case 90: ret = capget(rec->a1, rec->a2); break;
		case 91: ret = capset(rec->a1, rec->a2); break;
		case 92: ret = personality(rec->a1); break;
		case 93: exit(rec->a1); break;
//		case 94: ret = exit_group(rec->a1); break;
		case 94: ret = syscall(call, rec->a1); break;
		case 95: ret = waitid(rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 96: ret = set_tid_address(rec->a1); break;
		case 96: ret = syscall(call, rec->a1); break;
		case 97: ret = unshare(rec->a1); break;
//		case 98: ret = futex(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 98: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 99: ret = set_robust_list(rec->a1, rec->a2); break;
		case 99: ret = syscall(call, rec->a1, rec->a2); break;
//		case 100: ret = get_robust_list(rec->a1, rec->a2, rec->a3); break;
		case 100: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 101: ret = nanosleep(rec->a1, rec->a2); break;
		case 102: ret = getitimer(rec->a1, rec->a2); break;
		case 103: ret = setitimer(rec->a1, rec->a2, rec->a3); break;
//		case 104: ret = kexec_load(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 104: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 105: ret = init_module(rec->a1, rec->a2, rec->a3); break;
		case 106: ret = delete_module(rec->a1, rec->a2); break;
		case 107: ret = timer_create(rec->a1, rec->a2, rec->a3); break;
		case 108: ret = timer_gettime(rec->a1, rec->a2); break;
		case 109: ret = timer_getoverrun(rec->a1); break;
		case 110: ret = timer_settime(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 111: ret = timer_delete(rec->a1); break;
		case 112: ret = clock_settime(rec->a1, rec->a2); break;
		case 113: ret = clock_gettime(rec->a1, rec->a2); break;
		case 114: ret = clock_getres(rec->a1, rec->a2); break;
		case 115: ret = clock_nanosleep(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 116: ret = syslog(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 117: ret = ptrace(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 118: ret = sched_setparam(rec->a1, rec->a2); break;
		case 119: ret = sched_setscheduler(rec->a1, rec->a2, rec->a3); break;
		case 120: ret = sched_getscheduler(rec->a1); break;
		case 121: ret = sched_getparam(rec->a1, rec->a2); break;
		case 122: ret = sched_setaffinity(rec->a1, rec->a2, rec->a3); break;
		case 123: ret = sched_getaffinity(rec->a1, rec->a2, rec->a3); break;
		case 124: ret = sched_yield(); break;
		case 125: ret = sched_get_priority_max(rec->a1); break;
		case 126: ret = sched_get_priority_min(rec->a1); break;
		case 127: ret = sched_rr_get_interval(rec->a1, rec->a2); break;
//		case 128: ret = restart_syscall(); break;
		case 128: ret = syscall(call); break;
		case 129: ret = kill(rec->a1, rec->a2); break;
//		case 130: ret = tkill(rec->a1, rec->a2); break;
		case 130: ret = syscall(call, rec->a1, rec->a2); break;
//		case 131: ret = tgkill(rec->a1, rec->a2, rec->a3); break;
		case 131: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 132: ret = sigaltstack(rec->a1, rec->a2); break;
		case 133: ret = sigsuspend(rec->a1); break;
//		case 133: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 134: ret = sigaction(rec->a1, rec->a2, rec->a3); break;
//		case 134: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 135: ret = sigprocmask(rec->a1, rec->a2, rec->a3); break;
//		case 135: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 136: ret = sigpending(rec->a1); break;
//		case 136: ret = syscall(call, rec->a1); break;
		case 137: ret = sigtimedwait(rec->a1, rec->a2, rec->a3); break;
//		case 137: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 138: ret = sigqueueinfo(rec->a1, rec->a2, rec->a3); break;
		case 138: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 139: ret = sigreturn(rec->a1); break;
		case 139: ret = syscall(call, rec->a1); break;
		case 140: ret = setpriority(rec->a1, rec->a2, rec->a3); break;
		case 141: ret = getpriority(rec->a1, rec->a2); break;
		case 142: ret = reboot(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 143: ret = setregid(rec->a1, rec->a2); break;
		case 144: ret = setgid(rec->a1); break;
		case 145: ret = setreuid(rec->a1, rec->a2); break;
		case 146: ret = setuid(rec->a1); break;
		case 147: ret = setresuid(rec->a1, rec->a2, rec->a3); break;
		case 148: ret = getresuid(rec->a1, rec->a2, rec->a3); break;
		case 149: ret = setresgid(rec->a1, rec->a2, rec->a3); break;
		case 150: ret = getresgid(rec->a1, rec->a2, rec->a3); break;
		case 151: ret = setfsuid(rec->a1); break;
		case 152: ret = setfsgid(rec->a1); break;
		case 153: ret = times(rec->a1); break;
		case 154: ret = setpgid(rec->a1, rec->a2); break;
		case 155: ret = getpgid(rec->a1); break;
		case 156: ret = getsid(rec->a1); break;
		case 157: ret = setsid(); break;
		case 158: ret = getgroups(rec->a1, rec->a2); break;
		case 159: ret = setgroups(rec->a1, rec->a2); break;
		case 160: ret = uname(); break;
//		case 160: ret = syscall(call); break;
		case 161: ret = sethostname(rec->a1, rec->a2); break;
		case 162: ret = setdomainname(rec->a1, rec->a2); break;
		case 163: ret = getrlimit(rec->a1, rec->a2); break;
		case 164: ret = setrlimit(rec->a1, rec->a2); break;
		case 165: ret = getrusage(rec->a1, rec->a2); break;
		case 166: ret = umask(rec->a1); break;
		case 167: ret = prctl(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 168: ret = getcpu(rec->a1, rec->a2, rec->a3); break;
		case 168: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 169: ret = gettimeofday(rec->a1, rec->a2); break;
		case 170: ret = settimeofday(rec->a1, rec->a2); break;
		case 171: ret = adjtimex(rec->a1); break;
		case 172: ret = getpid(); break;
		case 173: ret = getppid(); break;
		case 174: ret = getuid(); break;
		case 175: ret = geteuid(); break;
		case 176: ret = getgid(); break;
		case 177: ret = getegid(); break;
//		case 178: ret = gettid(); break;
		case 178: ret = syscall(call); break;
		case 179: ret = sysinfo(rec->a1); break;
		case 180: ret = mq_open(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 181: ret = mq_unlink(rec->a1); break;
		case 182: ret = mq_timedsend(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 183: ret = mq_timedreceive(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 184: ret = mq_notify(rec->a1, rec->a2); break;
//		case 185: ret = mq_getsetattr(rec->a1, rec->a2, rec->a3); break;
		case 185: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
		case 186: ret = msgget(rec->a1, rec->a2); break;
		case 187: ret = msgctl(rec->a1, rec->a2, rec->a3); break;
		case 188: ret = msgrcv(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 189: ret = msgsnd(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 190: ret = semget(rec->a1, rec->a2, rec->a3); break;
		case 191: ret = semctl(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 192: ret = semtimedop(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 193: ret = semop(rec->a1, rec->a2, rec->a3); break;
		case 194: ret = shmget(rec->a1, rec->a2, rec->a3); break;
		case 195: ret = shmctl(rec->a1, rec->a2, rec->a3); break;
		case 196: ret = shmat(rec->a1, rec->a2, rec->a3); break;
		case 197: ret = shmdt(rec->a1); break;
		case 198: ret = socket(rec->a1, rec->a2, rec->a3); break;
		case 199: ret = socketpair(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 200: ret = bind(rec->a1, rec->a2, rec->a3); break;
		case 201: ret = listen(rec->a1, rec->a2); break;
		case 202: ret = accept(rec->a1, rec->a2, rec->a3); break;
		case 203: ret = connect(rec->a1, rec->a2, rec->a3); break;
		case 204: ret = getsockname(rec->a1, rec->a2, rec->a3); break;
		case 205: ret = getpeername(rec->a1, rec->a2, rec->a3); break;
		case 206: ret = sendto(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 207: ret = recvfrom(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 208: ret = setsockopt(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 209: ret = getsockopt(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 210: ret = shutdown(rec->a1, rec->a2); break;
		case 211: ret = sendmsg(rec->a1, rec->a2, rec->a3); break;
		case 212: ret = recvmsg(rec->a1, rec->a2, rec->a3); break;
		case 213: ret = readahead(rec->a1, rec->a2, rec->a3); break;
		case 214: ret = brk(rec->a1); break;
		case 215: ret = munmap(rec->a1, rec->a2); break;
		case 216: ret = mremap(rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 217: ret = add_key(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 217: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 218: ret = request_key(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 218: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 219: ret = keyctl(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 219: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 220: ret = clone(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 221: ret = execve(rec->a1, rec->a2, rec->a3); break;
		case 222: ret = mmap(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 223: ret = fadvise64_64(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 223: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 224: ret = swapon(rec->a1, rec->a2); break;
		case 225: ret = swapoff(rec->a1); break;
		case 226: ret = mprotect(rec->a1, rec->a2, rec->a3); break;
		case 227: ret = msync(rec->a1, rec->a2, rec->a3); break;
		case 228: ret = mlock(rec->a1, rec->a2); break;
		case 229: ret = munlock(rec->a1, rec->a2); break;
		case 230: ret = mlockall(rec->a1); break;
		case 231: ret = munlockall(); break;
		case 232: ret = mincore(rec->a1, rec->a2, rec->a3); break;
		case 233: ret = madvise(rec->a1, rec->a2, rec->a3); break;
		case 234: ret = remap_file_pages(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 235: ret = mbind(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 235: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 236: ret = get_mempolicy(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 236: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 237: ret = set_mempolicy(rec->a1, rec->a2, rec->a3); break;
		case 237: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 238: ret = migrate_pages(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 238: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 239: ret = move_pages(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 239: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 240: ret = rt_tgsigqueueinfo(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 240: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 241: ret = perf_event_open(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 241: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 242: ret = accept4(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 243: ret = recvmmsg(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 244: ret = ni_syscall(); break;
		case 244: 
		case 245:
		case 246:
		case 247:
		case 248:
		case 249:
		case 250:
		case 251:
		case 252:
		case 253:
		case 254:
		case 255:
		case 256:
		case 257:
		case 258:
		case 259:
			  ret = syscall(call); break;
//		case 245: ret = ni_syscall(); break;
//		case 246: ret = ni_syscall(); break;
//		case 247: ret = ni_syscall(); break;
//		case 248: ret = ni_syscall(); break;
//		case 249: ret = ni_syscall(); break;
//		case 250: ret = ni_syscall(); break;
//		case 251: ret = ni_syscall(); break;
//		case 252: ret = ni_syscall(); break;
//		case 253: ret = ni_syscall(); break;
//		case 254: ret = ni_syscall(); break;
//		case 255: ret = ni_syscall(); break;
//		case 256: ret = ni_syscall(); break;
//		case 257: ret = ni_syscall(); break;
//		case 258: ret = ni_syscall(); break;
//		case 259: ret = ni_syscall(); break;
//		case 260: ret = wait4(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 260: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 261: ret = prlimit64(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 262: ret = fanotify_init(rec->a1, rec->a2, rec->a3); break;
		case 263: ret = fanotify_mark(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 264: ret = name_to_handle_at(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 265: ret = open_by_handle_at(rec->a1, rec->a2, rec->a3); break;
		case 266: ret = clock_adjtime(); break;
		case 267: ret = syncfs(rec->a1); break;
		case 268: ret = setns(rec->a1, rec->a2); break;
		case 269: ret = sendmmsg(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 270: ret = process_vm_readv(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
		case 271: ret = process_vm_writev(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5, rec->a6); break;
//		case 272: ret = kcmp(rec->a1); break;
		case 272: ret = syscall(call, rec->a1); break;
//		case 273: ret = finit_module(rec->a1, rec->a2, rec->a3); break;
		case 273: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 274: ret = sched_setattr(rec->a1, rec->a2, rec->a3); break;
		case 274: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 275: ret = sched_getattr(rec->a1, rec->a2, rec->a3, rec->a4); break;
		case 275: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4); break;
//		case 276: ret = renameat2(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 276: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
//		case 277: ret = seccomp(rec->a1, rec->a2, rec->a3); break;
		case 277: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 278: ret = getrandom(rec->a1, rec->a2, rec->a3); break;
		case 278: ret = syscall(call, rec->a1, rec->a2, rec->a3); break;
//		case 279: ret = memfd_create(rec->a1, rec->a2); break;
		case 279: ret = syscall(call, rec->a1, rec->a2); break;
//		case 280: ret = bpf(); break;
		case 280: ret = syscall(call); break;
//		case 281: ret = execveat(rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		case 281: ret = syscall(call, rec->a1, rec->a2, rec->a3, rec->a4, rec->a5); break;
		default: break;
	}

	if(system(rmmod_cmd) < 0) {
                printf("insmod error\n");
        }

	return ret;
}
