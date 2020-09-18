override CFLAGS += -O0 -pthread -Wno-attributes
CC=gcc

#BINARIES=test kaslr physical_reader

SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:%.c=%)

all: $(BINARIES)

libkdump/libkdump.a:  libkdump/libkdump.c
	make -C libkdump

libkdump_32/libkdump.a:  libkdump_32/libkdump.c
	make -C libkdump

app_32/%: app_32/%.c libkdump_32/libkdump.a
	$(CC) $< -o $@ -m64 -Llibkdump_32 -Ilibkdump_32 -lkdump -static $(CFLAGS)

%: %.c libkdump/libkdump.a
	$(CC) $< -o $@ -m64 -Llibkdump -Ilibkdump -lkdump -Llibsgxstep -lsgx-step -static $(CFLAGS)
	
	
clean:
	rm -f *.o $(BINARIES)
	make clean -C libkdump
