#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
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
#include <sched.h>

#include <unistd.h>
#include <linux/random.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/kcmp.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <mqueue.h>
#include <sys/types.h>
#include <linux/kexec.h>
#include <linux/futex.h>
#include <syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <linux/unistd.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <linux/aio_abi.h>
#include <sys/epoll.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <poll.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <mqueue.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/socket.h>

#include "random.h"

static unsigned long handle_arg_address(struct syscallrecord *rec, unsigned int argnum)
{
        unsigned long addr = 0;

        if (argnum == 1)
                return (unsigned long) get_address();

        if (RAND_BOOL())
                return (unsigned long) get_address();

        /* Half the time, we look to see if earlier args were also ARG_ADDRESS,
         * and munge that instead of returning a new one from get_address() */

        addr = find_previous_arg_address(rec, argnum);

        switch (rand() % 4) {
        case 0: break;  /* return unmodified */
        case 1: addr++;
                break;
        case 2: addr+= sizeof(int);
                break;
        case 3: addr+= sizeof(long);
                break;
        }

        return addr;
}

struct itimerval* set_itimerval_arg()
{
	struct itimerval *p = NULL;

	p = (struct itimerval*)malloc(sizeof(struct itimerval));

	p->it_interval.tv_sec = (unsigned long) rand64() % 60;
	p->it_interval.tv_usec = (unsigned long) rand64();
	p->it_value.tv_sec = (unsigned long) rand64() % 60;
	p->it_value.tv_usec = (unsigned long) rand64();

	printf("parameter value: p->it_interval.tv_sec=%u, p->it_interval.tv_usec=%u, p->it_value.tv_sec=%u, p->it_value.tv_usec=%u,", 
		p->it_interval.tv_sec, p->it_interval.tv_usec, p->it_value.tv_sec, p->it_value.tv_usec);

	return p;
}

struct itimerspec *get_itimerspec()
{
	struct itimerspec *p = malloc(sizeof(struct itimerspec));

	p->it_interval.tv_sec = (unsigned long) rand64() % 60;
	p->it_interval.tv_nsec = (unsigned long) rand64();
	p->it_value.tv_sec = (unsigned long) rand64() % 60;
        p->it_value.tv_nsec = (unsigned long) rand64();

	printf("parameter value: p->it_interval.tv_sec=%u, p->it_interval.tv_nsec=%u, p->it_value.tv_sec=%u, p->it_value.tv_nsec=%u,",
                p->it_interval.tv_sec, p->it_interval.tv_nsec, p->it_value.tv_sec, p->it_value.tv_nsec);

        return p;
}

struct epoll_event *get_epoll_event()
{
	struct epoll_event *p = malloc(sizeof(struct epoll_event));

	p->events = (unsigned long) rand64();
	p->data.u64 = (unsigned long) rand64();

	printf("parameter value: p->events=%u, p->data.u64=%u,", 
		p->events, p->data.u64);

	return p;
}

struct statfs *get_statfs(struct syscallrecord *rec, unsigned int argnum)
{
	struct statfs *p = malloc(sizeof(struct statfs));

	p->f_type = (unsigned long) rand64();
	p->f_bsize = (unsigned long) get_len();
	p->f_blocks = (unsigned long) rand64();
	p->f_bfree = (unsigned long) rand64();
	p->f_bavail = (unsigned long) rand64();

	p->f_files = (unsigned long) rand64();
	p->f_ffree = (unsigned long) rand64();
	p->f_namelen = (unsigned long) get_len();

	printf("parameter value: p->f_type=%u, p->f_bsize=%u, p->f_blocks=%u, p->f_bfree=%u, p->f_bavail=%u, p->f_files=%u, p->f_ffree=%u,p->f_namelen=%u,",
		p->f_type, p->f_bsize, p->f_blocks, p->f_bfree, p->f_bavail, p->f_files, p->f_ffree, p->f_namelen);

	return p;
}

struct pollfd *get_pollfd()
{
	struct pollfd *p = malloc(sizeof(struct pollfd));

	p->fd = get_random_fd();
	p->events =  (unsigned long) rand64() % 255;
	p->revents = (unsigned long) rand64() % 255;

	printf("parameter value: p->fd=%u, p->events=%u, p->revents=%u,",
		p->fd, p->events, p->revents);

	return p;
}

struct sigaction *get_sigaction(struct syscallrecord *rec, unsigned int argnum)
{
	struct sigaction *p = malloc(sizeof(struct sigaction));

	p->sa_handler = handle_arg_address(rec, argnum);
	p->sa_sigaction = handle_arg_address(rec, argnum);
	p->sa_flags = (int) rand64();
	p->sa_restorer = handle_arg_address(rec, argnum);

	printf("parameter value: p->sa_handler=%u, p->sa_sigaction=%u, p->sa_flags=%u, p->sa_restorer=%u,",
		p->sa_handler, p->sa_sigaction, p->sa_flags, p->sa_restorer);

	return p;
}

struct tms *get_tms()
{
	struct tms *p = malloc(sizeof(struct tms));

	p->tms_utime = (long) rand64();
	p->tms_stime = (long) rand64();
	p->tms_cutime = (long) rand64();
	p->tms_cstime = (long) rand64();

	printf("parameter value: p->tms_utime=%u, p->tms_stime=%u, p->tms_cutime=%u, p->tms_cstime=%u,",
		p->tms_utime, p->tms_stime, p->tms_cutime, p->tms_cstime);

	return p;
}

struct utsname *get_utsname()
{
	struct utsname *p = malloc(sizeof(struct utsname));

	p->sysname[0] = generate_pathname();
	p->nodename[0] = generate_pathname();
	p->release[0] = generate_pathname();
	p->version[0] = generate_pathname();
	p->machine[0] = generate_pathname();

	printf("parameter value: p->sysname=%s, p->nodename=%s, p->release=%s, p->version=%s, p->machine=%s,",
		p->sysname, p->nodename, p->release, p->version, p->machine);

	return p;
}

struct rlimit *get_rlimit()
{
    struct rlimit *p2 = malloc(sizeof(struct rlimit));
    p2->rlim_max = (unsigned long) rand64();
    p2->rlim_cur = (unsigned long) rand64();
    printf("parameter value: p2->rlim_max=%u, p2->rlim_cur=%u,",
           p2->rlim_max, p2->rlim_cur);
    return p2;
}

struct timeval *get_timeval()
{
    struct timeval *p1 = malloc(sizeof(struct timeval));
    p1->tv_sec = (unsigned long) rand64() % 60;
    p1->tv_usec = (unsigned long) rand64();
    printf("parameter value: p1->tv_sec=%u, p1->tv_usec=%u,", p1->tv_sec,
           p1->tv_usec);
    return p1;
}

struct timex *get_timex()
{
	struct timex *p = malloc(sizeof(struct timex));

	p->modes = (int) rand64();
	p->offset = (long) rand64();
	p->freq = (long) rand64();
	p->maxerror = (long) rand64();
	p->esterror = (long) rand64();
	p->status = (int) rand64();
	p->constant = (long) rand64();
	p->precision = (long) rand64();
	p->tolerance = (long) rand64();

	p->time.tv_sec = (unsigned long) rand64() % 60;
	p->time.tv_usec = (unsigned long) rand64();

	p->tick = (long) rand64();
	p->ppsfreq = (long) rand64();
	p->jitter = (long) rand64();
	p->shift = (int) rand64();
	p->stabil = (long) rand64();
	p->jitcnt = (long) rand64();
	p->calcnt = (long) rand64();
	p->errcnt = (long) rand64();
	p->stbcnt = (long) rand64();
	p->tai = (int) rand64();

	printf("parameter value: p->modes=%u, p->offset=%u, p->freq=%u, p->maxerror=%u, p->esterror=%u, p->status=%u, p->constant=%u, \
			p->precision=%u, p->tolerance=%u, p->time.tv_sec=%u, p->time.tv_usec=%u, p->tick=%u, p->ppsfreq=%u, \
			p->jitter=%u, p->shift=%u, p->stabil=%u, p->jitcnt=%u, p->calcnt=%u, p->errcnt=%u, p->stbcnt=%u, p->tai=%u,",
		p->modes, p->offset, p->freq, p->maxerror, p->esterror, p->status, p->constant,
			p->precision, p->tolerance, p->time.tv_sec, p->time.tv_usec, p->tick, p->ppsfreq,
			p->jitter, p->shift, p->stabil, p->jitcnt, p->calcnt, p->errcnt, p->stbcnt, p->tai);

	return p;
}

struct mq_attr *get_mq_attr()
{
	struct mq_attr *p = malloc(sizeof(struct mq_attr));

	p->mq_flags = (long) rand64();
	p->mq_maxmsg = (long) rand64();
	p->mq_msgsize = (long) rand64();
	p->mq_curmsgs = (long) rand64();

	printf("parameter value: p->mq_flags=%u, p->mq_maxmsg=%u, p->mq_msgsize=%u, p->mq_curmsgs=%u,",
			p->mq_flags, p->mq_maxmsg, p->mq_msgsize, p->mq_curmsgs);

	return p;
}

struct msqid_ds *get_msqid_ds()
{
	struct msqid_ds *p = malloc(sizeof(struct msqid_ds));

	p->msg_perm.__key = (long) rand64();
	p->msg_perm.uid = (long) rand64();
	p->msg_perm.gid = (long) rand64();
	p->msg_perm.cuid = (long) rand64();
        p->msg_perm.cgid = (long) rand64();
	p->msg_perm.mode = (long) rand64();
        p->msg_perm.__seq = (long) rand64();

	p->msg_stime = (long) rand64();
	p->msg_rtime = (long) rand64();
	p->msg_ctime = (long) rand64();
	p->__msg_cbytes = (long) rand64();
	p->msg_qnum = (long) rand64();
	p->msg_qbytes = (long) rand64();
	p->msg_lspid = (long) rand64();
	p->msg_lrpid = (long) rand64();

	printf("parameter value: p->msg_perm.__key=%u, p->msg_perm.uid=%u, p->msg_perm.gid=%u, p->msg_perm.cuid=%u, p->msg_perm.cgid=%u, \
			p->msg_perm.mode=%u, p->msg_perm.__seq=%u, p->msg_stime=%u, p->msg_rtime=%u, p->msg_ctime=%u, p->__msg_cbytes=%u, \
			p->msg_qnum=%u, p->msg_qbytes=%u, p->msg_lspid=%u, p->msg_lrpid=%u,",
		p->msg_perm.__key, p->msg_perm.uid, p->msg_perm.gid, p->msg_perm.cuid, p->msg_perm.cgid,
			p->msg_perm.mode, p->msg_perm.__seq, p->msg_stime, p->msg_rtime, p->msg_ctime, p->__msg_cbytes,
			p->msg_qnum, p->msg_qbytes, p->msg_lspid, p->msg_lrpid);

	return p;
}

struct sembuf *get_sembuf()
{
	struct sembuf *p = malloc(sizeof(struct sembuf));

	p->sem_num = (unsigned short) rand64();
	p->sem_op = (short) rand64();
	p->sem_flg = (short) rand64();

	printf("parameter value: p->sem_num=%u, p->sem_op=%u, p->sem_flg=%u,", p->sem_num, p->sem_op, p->sem_flg);

	return p;
}

struct msghdr *get_msghdr(struct syscallrecord *rec, unsigned int argnum)
{
	struct msghdr *p = malloc(sizeof(struct msghdr));

	p->msg_name = generate_pathname();
	p->msg_namelen = (unsigned long) get_len();

	p->msg_iov->iov_len = handle_arg_address(rec, argnum);
	p->msg_iov->iov_base = (unsigned long) get_len();

	p->msg_iovlen = (unsigned long) get_len();
	p->msg_control = (unsigned long) get_len();
	p->msg_controllen = (unsigned long) get_len();
	p->msg_flags = MSG_EOR;

	printf("parameter value: p->msg_name=%s, p->msg_namelen=%u, p->msg_iovlen=%u, p->msg_control=%u, p->msg_controllen=%u, p->msg_flags=%u,",
		p->msg_name, p->msg_namelen, p->msg_iovlen, p->msg_control, p->msg_controllen, p->msg_flags);

	return p;
}

struct file_handle *get_file_handle()
{
    struct file_handle *p3 = malloc(sizeof(struct file_handle));
    p3->handle_type = (int) rand64();
    p3->handle_bytes = (unsigned int) rand64();
    printf
        ("parameter value: p3->handle_type=%u, p3->handle_bytes=%u,",
         p3->handle_type, p3->handle_bytes);
    return p3;
}

struct rusage *get_rusage()
{
	struct rusage *p = malloc(sizeof(struct rusage));

	p->ru_utime.tv_sec = (unsigned long) rand64() % 60;
	p->ru_utime.tv_usec = (unsigned long) rand64();
	p->ru_stime.tv_sec = (unsigned long) rand64() % 60;
	p->ru_stime.tv_usec = (unsigned long) rand64();

	p->ru_maxrss = (long) rand64();
	p->ru_ixrss = (long) rand64();
	p->ru_idrss = (long) rand64();
	p->ru_isrss = (long) rand64();
	p->ru_minflt = (long) rand64();
	p->ru_majflt = (long) rand64();
	p->ru_nswap = (long) rand64();
	p->ru_inblock = (long) rand64();
	p->ru_oublock = (long) rand64();
	p->ru_msgsnd = (long) rand64();
	p->ru_msgrcv = (long) rand64();
	p->ru_nsignals = (long) rand64();
	p->ru_nvcsw = (long) rand64();
	p->ru_nivcsw = (long) rand64();

	printf("parameter value: p->ru_utime.tv_sec=%u, p->ru_utime.tv_usec=%u, p->ru_stime.tv_sec=%u, p->ru_stime.tv_usec=%u, p->ru_maxrss=%u, \
			p->ru_ixrss=%u, p->ru_idrss=%u, p->ru_isrss=%u, p->ru_minflt=%u, p->ru_majflt=%u, p->ru_nswap=%u, p->ru_inbloc=%u, p->ru_oublock=%u, \
			p->ru_msgsnd=%u, p->ru_msgrcv=%u, p->ru_nsignals=%u, p->ru_nvcsw=%u, p->ru_nivcsw=%u,",
		p->ru_utime.tv_sec, p->ru_utime.tv_usec, p->ru_stime.tv_sec, p->ru_stime.tv_usec, p->ru_maxrss,
			p->ru_ixrss, p->ru_idrss, p->ru_isrss, p->ru_minflt, p->ru_majflt, p->ru_nswap, p->ru_inblock, p->ru_oublock,
			p->ru_msgsnd, p->ru_msgrcv, p->ru_nsignals, p->ru_nvcsw, p->ru_nivcsw);

	return p;
}

struct sigevent *get_sigevent(struct syscallrecord *rec, unsigned int argnum)
{
    struct sigevent *p2 = malloc(sizeof(struct sigevent));
    p2->sigev_notify = (int) rand64();
    p2->_sigev_un._pad[0] = rand64();
    p2->_sigev_un._pad[1] = rand64();
    p2->_sigev_un._pad[2] = rand64();
    p2->_sigev_un._pad[3] = rand64();
    p2->_sigev_un._pad[4] = rand64();
    p2->_sigev_un._pad[5] = rand64();
    p2->_sigev_un._pad[6] = rand64();
    p2->_sigev_un._pad[7] = rand64();
    p2->_sigev_un._pad[8] = rand64();
    p2->_sigev_un._pad[9] = rand64();
    p2->_sigev_un._pad[10] = rand64();
    p2->_sigev_un._pad[11] = rand64();
    p2->_sigev_un._pad[12] = rand64();
    p2->_sigev_un._tid = rand64();
    p2->_sigev_un._sigev_thread._function = handle_arg_address(rec, argnum);
    p2->_sigev_un._sigev_thread._attribute = rand64();
    p2->sigev_signo = (int) rand64();
    p2->sigev_value.sival_int = rand64();
    p2->sigev_value.sival_ptr = handle_arg_address(rec, argnum);
    printf
        ("parameter value: p2->sigev_notify=%u, p2->_sigev_un._pad[0]=%u, p2->_sigev_un._pad[1]=%u, p2->_sigev_un._pad[2]=%u, p2->_sigev_un._pad[3]=%u, p2->_sigev_un._pad[4]=%u, p2->_sigev_un._pad[5]=%u, p2->_sigev_un._pad[6]=%u, p2->_sigev_un._pad[7]=%u, p2->_sigev_un._pad[8]=%u, p2->_sigev_un._pad[9]=%u, p2->_sigev_un._pad[10]=%u, p2->_sigev_un._pad[11]=%u, p2->_sigev_un._pad[12]=%u, p2->_sigev_un._tid=%u, p2->_sigev_un._sigev_thread._function=%u, p2->_sigev_un._sigev_thread._attribute=%u, p2->sigev_signo=%u, p2->sigev_value.sival_int=%u, p2->sigev_value.sival_ptr=%u,",
         p2->sigev_notify, p2->_sigev_un._pad[0], p2->_sigev_un._pad[1],
         p2->_sigev_un._pad[2], p2->_sigev_un._pad[3],
         p2->_sigev_un._pad[4], p2->_sigev_un._pad[5],
         p2->_sigev_un._pad[6], p2->_sigev_un._pad[7],
         p2->_sigev_un._pad[8], p2->_sigev_un._pad[9],
         p2->_sigev_un._pad[10], p2->_sigev_un._pad[11],
         p2->_sigev_un._pad[12], p2->_sigev_un._tid,
         p2->_sigev_un._sigev_thread._function,
         p2->_sigev_un._sigev_thread._attribute, p2->sigev_signo,
         p2->sigev_value.sival_int, p2->sigev_value.sival_ptr);
    return p2;
}

struct sched_param *get_sched_param()
{
    struct sched_param *p2 = malloc(sizeof(struct sched_param));
    p2->__sched_priority = (int)rand64();
    printf("parameter value: p2->__sched_priority=%u,",
           p2->__sched_priority);
    return p2;
}

struct timezone *get_timezone()
{
    struct timezone *p2 = malloc(sizeof(struct timezone));
    p2->tz_dsttime = (unsigned long) rand64();
    p2->tz_minuteswest = (unsigned long) rand64();
    printf("parameter value: p2->tz_dsttime=%u, p2->tz_minuteswest=%u,",
           p2->tz_dsttime, p2->tz_minuteswest);
    return p2;
}

struct iovec *get_iovec(struct syscallrecord *rec, unsigned int argnum)
{
    struct iovec *p2 = malloc(sizeof(struct iovec));
    p2->iov_len = handle_arg_address(rec, argnum);
    p2->iov_base = (unsigned long) get_len();

    printf("parameter value: p2->iov_len=%u, p2->iov_base=%u,",
           p2->iov_len, p2->iov_base);
    return p2;
}

struct timespec *get_timespec()
{
    struct timespec *p3 = malloc(sizeof(struct timespec));
    p3->tv_sec = (unsigned long) rand64() % 60;
    p3->tv_nsec = (unsigned long) rand64() % 1000 ;
    printf("parameter value: p3->tv_sec=%u, p3->tv_nsec=%u,", p3->tv_sec,
           p3->tv_nsec);
    return p3;
}

