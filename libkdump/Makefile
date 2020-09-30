SGX_SDK = /opt/intel/sgxsdk
override CFLAGS += -O0 -pthread -Wno-attributes

CC          = gcc
AR          = ar
ARFLAGS     = -rcs

INCLUDE     = -I$(SGX_SDK)/include/
SOURCES     = $(shell ls *.c)
ASM         = $(shell ls *.S)
OBJECTS     = $(SOURCES:.c=.o) $(ASM:.S=.o)
OUTPUT      = libkdump.a libkdump.so

all: $(OUTPUT)

libkdump.a: $(OBJECTS)
	$(AR) $(ARFLAGS) libkdump.a $(OBJECTS)

libkdump.so: $(OBJECTS)
	$(CC) -shared -m64 -Wl,-soname,libkdump.so -o libkdump.so $(OBJECTS) $(CFLAGS)

%.o : %.c
	$(CC) $(CFLAGS) -m64 -fPIC $(INCLUDE) -c $<

%.o : %.S
	$(AS) $(INCLUDE) -c $< -o $@

install: libkdump.a libkdump.so
	cp libkdump.so /usr/local/lib
	cp libkdump.h /usr/local/include
	ldconfig
	
uninstall: 
	rm /usr/local/lib/libkdump.so
	rm /usr/local/include/libkdump.h
	ldconfig

clean:
	rm -f $(OBJECTS) $(OUTPUT)
