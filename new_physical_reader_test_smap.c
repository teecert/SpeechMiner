#include "libkdump.h"
#include "libsgxstep/pt.h"
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

  int value = libkdump_window_measure((size_t)dummy_secret, (size_t)dummy_secret, 
    MELTDOWN_SMAP, CACHE_LEVEL_L1, TLB_PRESENT, 0x42);
  printf("window size %d\n", value);
  fflush(stdout);

  libkdump_cleanup();

  return 0;
}
