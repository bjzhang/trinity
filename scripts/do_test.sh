#!/bin/bash

#array_syscalls=(setxattr getxattr lsetxattr fsetxattr lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr getcwd lookup_dcookie eventfd2 epoll_create1
#                dup dup3 mount unlinkat fcntl inotify_init1 inotify_add_watch inotify_rm_watch ioctl flock mknodat mkdirat symlinkat linkat renameat umount pivot_root truncate ftruncate
#                fallocate chdir fchdir chroot fchownat fchown openat pipe2 quotactl lseek read write sendfile splice tee readlinkat capget capset
#                fsync fdatasync sync_file_range timerfd_create acct personality unshare init_module delete_module timer_getoverrun timer_delete
#                sched_getscheduler sched_setaffinity sched_getaffinity sched_get_priority_max sched_get_priority_min 
#                setpriority getpriority setregid setgid setreuid setuid setresuid getresuid setresgid getresgid setfsuid setfsgid setpgid getpgid getsid getgroups
#                setgroups sethostname setdomainname umask prctl mq_unlink msgget msgrcv msgsnd semget shmget shmat shmdt socket socketpair listen sendto
#                shutdown munmap mremap add_key request_key swapon swapoff mprotect msync mlock munlock mlockall mincore madvise remap_file_pages
#                accept4 fanotify_init fanotify_mark syncfs setns renameat2 getrandom memfd_create)
array_syscalls=(setpriority setregid setreuid setuid setresuid setresgid semget prctl timer_delete sched_get_priority_min sched_get_priority_max getpriority msgsnd mremap)

array_num=${#sdk_common[@]}

DIR=`pwd`

trinity_bin="/tmp/trinity"
N=3

target_ip=9.84.16.1

TEST_N=
PARA_N=

setup() {
	rm -rf $DIR/log
}

run_trinity() {
	ssh root@$target_ip "cd /tmp;$trinity_bin --dangerous -c$test_syscall -N$N -C1" &> $trinity_log
}

create_glibc_log() {
	local log=tmp_log
	local i

	cat $trinity_log |grep "syscall message" > $log

	TEST_N=`cat $log |wc -l`
	local tmp_n=`grep -o "=" $log |wc -l`

	if [ $TEST_N -eq 0 ]; then
		echo "=can't find $log," >> $glibc_log
		return 1
	else
		PARA_N=$(($tmp_n / $TEST_N))
	fi

	rm $glibc_log
	while read line
	do
		local PARA=
		for ((i=1; i<=$PARA_N; i++))
		do
			if [ "$i" == "1" ]; then
				PARA=`echo $line |awk -F"=" '{print $(j+1)}' j=$i |awk -F"," '{print $1}'`
			else
				PARA="$PARA `echo $line |awk -F"=" '{print $(j+1)}' j=$i |awk -F"," '{print $1}'`"
			fi

			echo "i=$i, `echo $line |awk -F"=" '{print $(j+1)}' j=$i |awk -F"," '{print $1}'`"
		done

		echo $PARA >> $glibc_log
	done < $log

	rm $log
}

create_kernel_log() {
	rm $kernel_log

	ssh root@$target_ip "dmesg -c" &> $kernel_log
}

#############################################################
# paramter
#############################################################
p_N=6
glibc_p=
kernel_p=
deal_glibc_p()
{
	p_line=`cat $glibc_log |head -n 1`

	for ((i=1; i<=$p_N; i++))
	do
		# get param from $glibc_log
		tmp_p="`echo $p_line |awk -F" " '{print $j}' j=$i`"

		# delete "
		tmp_p=`echo $tmp_p |sed 's/\"//g'`

		# change 0x to %ld
		echo $tmp_p |grep "0x" >/dev/null
		if [ $? -eq 0 ]; then
			D=`echo $tmp_p |sed 's/0x//g'`
			tmp_p=`echo $((16#$D))`
		fi
		
		glibc_p[$i]="$tmp_p"
		echo "$i: ${glibc_p[$i]}"
	done
}

deal_kernel_p()
{
	p_line=`cat $kernel_log |head -n 1`

	for ((i=1; i<=$p_N; i++))
        do
                # get param from $glibc_log
                tmp_p="`echo $p_line |awk -F"<" '{print $(j+1)}' j=$i |awk -F">" '{print $1}'`"

                # delete "
                tmp_p=`echo $tmp_p |sed 's/\"//g'`

                # change 0x to %ld
                echo $tmp_p |grep "0x" >/dev/null
                if [ $? -eq 0 ]; then
                        D=`echo $tmp_p |sed 's/0x//g'`
                        tmp_p=`echo $((16#$D))`
                fi

                kernel_p[$i]=$tmp_p
		echo "$i: ${kernel_p[$i]}"
        done
}

#############################################################
# compare
#############################################################
result_e=$DIR/log/result.error
result_p=$DIR/log/result.pass
result_c=$DIR/log/result.check
compare()
{
	local ret=0

	echo "$test_syscall:" >> $result_c

	for ((i=1; i<=$p_N; i++))
	do
		if [ -z "${glibc_p[$i]}" ]; then
			continue
		fi

		cat $kernel_log |grep "${glibc_p[$i]}"
		if [ $? -ne 0 ]; then
#		if [ "${glibc_p[$i]}" != "${kernel_p[$i]}" ]; then
			ret=$(($ret+1))
		fi

		echo "$i: glibc:${glibc_p[$i]}" >> $result_c
	done

	if [ $ret -eq 0 ]; then
		echo "PASS $test_syscall" >> ${result_p}
	else
		echo "FAIL $test_syscall" >> ${result_e}
	fi
}


rmmod_all()
{
	local ls_mod=`ssh root@$target_ip "lsmod"`
        local target_mod=`echo $ls_mod |grep 0 |awk -F" " '{print $1}'`
        
	if [ -n "$target_mod" ]; then
		ssh root@$target_ip "rmmod $target_mod"
	fi
}

setup

for test_syscall in ${array_syscalls[@]}
do
	ssh root@$target_ip "dmesg -c" &>/dev/null

	log_dir=$DIR/log/$test_syscall
	trinity_log=$log_dir/trinity.log
	kernel_log=$log_dir/kernel.log
	glibc_log=$log_dir/glibc.log

	mkdir -p $log_dir

	run_trinity

	create_kernel_log

	create_glibc_log

	deal_glibc_p

#	deal_kernel_p

	compare

	rmmod_all
done

exit 0
