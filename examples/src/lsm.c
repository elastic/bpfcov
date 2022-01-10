// SPDX-License-Identifier: GPL-2.0

/*
 * Adapted from:
 * https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/test_lsm.c
 */

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include "lsm.skel.h"

void test__fail(void) {}

#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		test__fail();						\
		fprintf(stdout, "%s:FAIL:%s ", __func__, tag);		\
		fprintf(stdout, ##format);				\
	} else {							\
		fprintf(stdout, "%s:PASS:%s %d nsec\n",			\
		       __func__, tag, duration);			\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)

#define ASSERT_EQ(actual, expected, name) ({				\
	static int duration = 0;					\
	typeof(actual) ___act = (actual);				\
	typeof(expected) ___exp = (expected);				\
	bool ___ok = ___act == ___exp;					\
	CHECK(!___ok, (name),						\
	      "unexpected %s: actual %lld != expected %lld\n",		\
	      (name), (long long)(___act), (long long)(___exp));	\
	___ok;								\
})

#define ASSERT_OK(res, name) ({						\
	static int duration = 0;					\
	long long ___res = (res);					\
	bool ___ok = ___res == 0;					\
	CHECK(!___ok, (name), "unexpected error: %lld (errno %d)\n",	\
	      ___res, errno);						\
	___ok;								\
})

#define ASSERT_ERR_PTR(ptr, name) ({					\
	static int duration = 0;					\
	const void *___res = (ptr);					\
	int ___err = libbpf_get_error(___res);				\
	bool ___ok = ___err != 0;					\
	CHECK(!___ok, (name), "unexpected pointer: %p\n", ___res);	\
	___ok;								\
})

#define ASSERT_OK_PTR(ptr, name) ({					\
	static int duration = 0;					\
	const void *___res = (ptr);					\
	int ___err = libbpf_get_error(___res);				\
	bool ___ok = ___err == 0;					\
	CHECK(!___ok, (name), "unexpected error: %d\n", ___err);	\
	___ok;								\
})

char *CMD_ARGS[] = {"true", NULL};

#define GET_PAGE_ADDR(ADDR, PAGE_SIZE) \
	(char *)(((unsigned long) (ADDR + PAGE_SIZE)) & ~(PAGE_SIZE-1))

int stack_mprotect(void)
{
	void *buf;
	long sz;
	int ret;

	sz = sysconf(_SC_PAGESIZE);
	if (sz < 0)
		return sz;

	buf = alloca(sz * 3);
	ret = mprotect(GET_PAGE_ADDR(buf, sz), sz, PROT_READ | PROT_WRITE | PROT_EXEC);
	return ret;
}

int exec_cmd(int *monitored_pid)
{
	int child_pid, child_status;

	child_pid = fork();
	if (child_pid == 0) {
		*monitored_pid = getpid();
		execvp(CMD_ARGS[0], CMD_ARGS);
		return -EINVAL;
	} else if (child_pid > 0) {
		waitpid(child_pid, &child_status, 0);
		return child_status;
	}

	return -EINVAL;
}

static int test_lsm(struct lsm *skel)
{
	struct bpf_link *link;
	int buf = 1234;
	int err;

	err = lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		return err;

	/* Check that already linked program can't be attached again. */
	link = bpf_program__attach(skel->progs.test_int_hook);
	if (!ASSERT_ERR_PTR(link, "attach_link"))
		return -1;

	err = exec_cmd(&skel->bss->monitored_pid);
	if (!ASSERT_OK(err, "exec_cmd"))
		return err;

	ASSERT_EQ(skel->bss->bprm_count, 1, "bprm_count");

	skel->bss->monitored_pid = getpid();

	err = stack_mprotect();
	if (!ASSERT_EQ(errno, EPERM, "stack_mprotect"))
		return err;

	ASSERT_EQ(skel->bss->mprotect_count, 1, "mprotect_count");

	syscall(__NR_setdomainname, &buf, -2L);
	syscall(__NR_setdomainname, 0, -3L);
	syscall(__NR_setdomainname, ~0L, -4L);

	ASSERT_EQ(skel->bss->copy_test, 3, "copy_test");

	lsm__detach(skel);

	skel->bss->copy_test = 0;
	skel->bss->bprm_count = 0;
	skel->bss->mprotect_count = 0;
	return 0;
}

int main(int argc, char **argv)
{
	struct lsm *skel = NULL;
	int err;

	skel = lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "lsm_skel_load"))
		goto close_prog;

	err = test_lsm(skel);
	if (!ASSERT_OK(err, "test_lsm_first_attach"))
		goto close_prog;

	err = test_lsm(skel);
	ASSERT_OK(err, "test_lsm_second_attach");

close_prog:
	lsm__destroy(skel);
}
