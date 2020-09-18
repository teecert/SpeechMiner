#include "libkdump.h"
#include "libsgxstep/pt.h"
// #include "libsgxstep/debug.h"
#include <stdio.h>
#include <stdlib.h>

size_t dummy_secret[80] = {0x42 << 12, 0x4 << 12, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0, 
                    0x42 << 12, 0x4 << 12, 0, 0, 0, 0, 0, 0, 0x42 << 12, 0, 0, 0, 0, 0, 0, 0};

int main(int argc, char *argv[]) {
  libkdump_enable_debug(1);

  libkdump_config_t config;
  config = libkdump_get_autoconfig();
  config.measurements = 3;
  config.retries = 10000;
  config.load_threads = 0;

  libkdump_init(config);

  uint64_t *shadow_secret = (uint64_t *)remap_page_table_level((void *)dummy_secret, PAGE);
  // set_reserved_bit((size_t)shadow_secret);
  // libkdump_flush_tlb((size_t)shadow_secret);
  printf("%p: %lx\n", dummy_secret, *dummy_secret);
  printf("%p: %lx\n", shadow_secret, *shadow_secret);
  // return 0;

  uint64_t *pte_encl = (uint64_t *)remap_page_table_level((void *)shadow_secret, PTE);
  printf("%p old pte: %lx\n", shadow_secret, *pte_encl);
  // mmap as shared page makes the page UC-; make sure it is cacheable using next line code
  *pte_encl = MARK_CACHEABLE( *pte_encl );
  *pte_encl = MARK_SUPERVISOR( *pte_encl );
  // *pte_encl = MARK_NOT_PRESENT( *pte_encl );
  // *pte_encl = MARK_RESERVED( *pte_encl );
  printf("%p new pte: %lx\n", shadow_secret, *pte_encl);
  libkdump_flush_tlb((size_t)shadow_secret);

  // while (1) {
    int value = libkdump_window_measure((size_t)shadow_secret, (size_t)dummy_secret, 
      MELTDOWN_STANDARD, CACHE_LEVEL_L1, TLB_DEFAULT, 0x42);
    printf("window size %d\n", value);
    fflush(stdout);
  // }

  libkdump_cleanup();

  return 0;
}
