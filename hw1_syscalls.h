#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/slab.h>

typedef struct sys_call_restriction {
	int syscall_num;
	int restriction_threshold;
} scr;

typedef struct forbidden_activity_info {
	int syscall_num;
	int syscall_restriction_threshold;
	int proc_restriction_level;
	int time;
} fai;

int sc_restrict (pid_t p1, int p2, scr* p3, int p4){
	unsigned int res;
	__asm__ (
		"int $0x80;"
		: "=a" (res)
		: "0" (243), "b" (p1), "c" (p2), "d" (p3), "S" (p4)
		: "memory"
	);
	if (res < 0)
	{
		errno = -res;
		res = -1;
	}
	return (int) res;
}

int set_proc_restriction (pid_t p1, int p2){
	unsigned int res;
	__asm__ (
		"int $0x80;"
		: "=a" (res)
		: "0" (244), "b" (p1), "c" (p2)
		: "memory"
	);
	if (res < 0)
	{
		errno = -res;
		res = -1;
	}
	return (int) res;
}

int get_process_log (pid_t p1, int p2, fai* p3){
	unsigned int res;
	__asm__ (
		"int $0x80;"
		: "=a" (res)
		: "0" (245), "b" (p1), "c" (p2), "d" (p3)
		: "memory"
	);
	if (res < 0)
	{
		errno = -res;
		res = -1;
	}
	return (int) res;
}
