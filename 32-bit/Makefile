override CFLAGS += -O0 -pthread -Wno-attributes
CC=gcc

#BINARIES=test kaslr physical_reader

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%)

all: $(BINARIES)

libkdump_32/libkdump.a:  libkdump_32/libkdump.c
	make -C libkdump_32

%: %.c libkdump_32/libkdump.a
	$(CC) $< -o $@ -m32 -Llibkdump_32 -Ilibkdump_32 -lkdump -static $(CFLAGS)
	
	
clean:
	rm -f *.o $(BINARIES)
	make clean -C libkdump_32
