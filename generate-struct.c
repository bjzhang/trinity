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
#include "generate-struct.h"
#include "random.h"

static struct itimerval* p = NULL;

struct itimerval* set_itimerval_arg()
{
//	static struct itimerval* p = NULL;

	p = (struct itimerval*)malloc(sizeof(struct itimerval));

	p->it_interval.tv_sec = (unsigned long) rand64() % 60;
	p->it_interval.tv_usec = (unsigned long) rand64() % 60;
	p->it_value.tv_sec = (unsigned long) rand64() % 60;
	p->it_value.tv_usec = (unsigned long) rand64() % 60;

//	printf("p:%d, sizeof(struct itimerval):%d p->it_interval.tv_sec=%d, p->it_interval.tv_usec=%d, p->it_value.tv_sec=%d, p->it_value.tv_usec=%d\n", 
//		p, sizeof(struct itimerval), p->it_interval.tv_sec, p->it_interval.tv_usec, p->it_value.tv_sec, p->it_value.tv_usec);

	return p;
}
