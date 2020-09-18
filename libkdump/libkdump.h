#ifndef _LIBKDUMP_H_
#define _LIBKDUMP_H_

#include <stdint.h>
#include <stdio.h>
// #include "sgx_urts.h"

#if !(defined(__x86_64__) || defined(__i386__))
# error x86-64 and i386 are the only supported architectures
#endif

#ifdef __x86_64__
#define DEFAULT_PHYSICAL_OFFSET 0xffff880000000000ull
#else
#define DEFAULT_PHYSICAL_OFFSET 0xc0000000ull
#endif

/**
 * libkdump exception handling
 */
typedef enum {
    SIGNAL_HANDLER, /**< Install a signal handler to catch SIGSEGV */
    TSX /**< Use Intel TSX to suppress exception */
} libkdump_fault_handling_t;


/**
 * libkdump load thread action
 */
typedef enum {
    NOP, /**< Just run an endless loop */
    IO, /**< Perform I/O operations to trigger interrupts */
    YIELD, /**< Continuously switch to the operating system */ 
    FPU
} libkdump_load_t;


/**
 * libkdump configuration
 */
typedef struct {
  size_t cache_miss_threshold; /**< Cache miss threshold in cycles for Flush+Reload */
  size_t l2_threshold;
  size_t l3_threshold;
  libkdump_fault_handling_t fault_handling; /**< Type of fault handling (TSX or signal handler) */
  int measurements; /**< Number of measurements to perform for one address */
  int accept_after; /**< How many measurements must be the same to accept the read value */
  int load_threads; /**< Number of threads which are started to increase the chance of reading from inaccessible addresses */
  libkdump_load_t load_type; /**< Function the load threads should execute */
  int retries; /**< Number of Meltdown retries for an address */
  size_t physical_offset; /**< Address of the physical direct map */
} libkdump_config_t;

extern libkdump_config_t libkdump_auto_config;

/**
 * Initializes libkdump
 *
 * @param[in] configuration The configuration for libkdump, or 'libkdump_auto_config' for auto configuration.
 *
 * @return 0 Initialization was successful
 * @return -1 Initialization failed, errno contains the error code
 */
int libkdump_init(const libkdump_config_t configuration);


/**
 * Returns a config to be used with libkdump_init. All parameters are automatically configured to sane defaults.
 *
 * @return A libkdump configuration (libkdump_config_t)
 */
libkdump_config_t libkdump_get_autoconfig();


/**
 * Reads one character from the given (virtual) address using Meltdown
 *
 * @param[in] addr The virtual address to read from
 * 
 * @return The read character
 */
int libkdump_read(size_t addr);


/**
 * Cleans up and reverts everything which was changed by libkdump.
 *
 * @return 0 Cleanup was successful
 * @return -1 Cleanup failed, errno contains the error code
 */
int libkdump_cleanup();


/**
 * Retrieves the physical address of a virtual address. Requires root (or read permissions for /proc/self/pagemap).
 *
 * @param[in] addr The virtual address to convert
 * 
 * @return The physical address, or 0 if an error occurred (errno contains the error code)
 */
size_t libkdump_virt_to_phys(size_t addr);


/**
 * Converts a physical address to a virtual address using the physical direct map offset.
 *
 * @param[in] addr The physical address to convert
 * 
 * @return The virtual address, or -1ULL if an error occured.
 */
size_t libkdump_phys_to_virt(size_t addr);


/**
 * Retrieves the physical address of a virtual address. Requires root (or read permissions for /proc/self/pagemap).
 *
 * @param[in] enable Enable (1) or disable (0) the debug output of libkdump. Default is disabled. 
 */
void libkdump_enable_debug(int enable);



size_t libkdump_get_data();
int libkdump_flush_tlb(size_t addr);
int set_reserved_bit(size_t addr);
int libkdump_kernel_read_CR4();
int libkdump_kernel_read_MSR(size_t addr);



int libkdump_prefetch_read(size_t addr, void *legal_addr,
  int cache_level, int tlb_flush, int expected_data);




#define MELTDOWN_STANDARD 0
#define MELTDOWN_CR 1
#define MELTDOWN_MSR 2
#define MELTDOWN_XMM 3
#define MELTDOWN_XMM_LOAD 4
#define MELTDOWN_XMM_WAIT 5
#define MELTDOWN_SMM 6
#define MELTDOWN_SMAP 7
#define MELTDOWN_PK_KERNEL 8
#define MELTDOWN_PK_USER 9
#define MELTDOWN_WRITE 10
#define MELTDOWN_SYSENTER 11
#define MELTDOWN_FORESHADOW 12

#define CACHE_LEVEL_MEMORY 0
#define CACHE_LEVEL_L1 1
#define CACHE_LEVEL_L2 2
#define CACHE_LEVEL_L3 3
#define CACHE_LEVEL_DEFAULT -1

#define TLB_NOT_PRESENT 0
#define TLB_PRESENT 1
#define TLB_DEFAULT -1



int libkdump_window_measure(size_t addr, size_t legal_addr,
  int code_type, int cache_level, int tlb_flush, int expected_data);

uint64_t libkdump_smm_prepare(int expected_data);

void libkdump_pk_prepare(size_t addr);

void libkdump_pk_restore();



void libkdump_spectre_prepare(size_t code_addr, size_t code_len);
int libkdump_spectre_read(size_t training_x, size_t malicious_x, int score[2], 
  uint8_t value[2], size_t tlb_preload_x, int code_type, int cache_level, int tlb_flush, int expected_data);
void libkdump_spectre_result(int score[2], uint8_t value[2]);
void libkdump_spectre_restore();



// typedef sgx_status_t (*Ecall)(sgx_enclave_id_t eid, int *type);
// void libkdump_set_ecall_pointer(Ecall func);
// void libkdump_set_eid(sgx_enclave_id_t eid);

#endif

