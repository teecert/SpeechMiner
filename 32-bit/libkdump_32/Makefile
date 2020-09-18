override CFLAGS += -O0 -pthread -Wno-attributes
CC=gcc

all: libkdump.a libkdump.so

libkdump.o: libkdump.c
	$(CC) -c -m32 -fPIC libkdump.c -o libkdump.o $(CFLAGS)
	
libkdump.so: libkdump.o
	$(CC) -shared -m32 -Wl,-soname,libkdump.so -o libkdump.so libkdump.o $(CFLAGS)
	
libkdump.a: libkdump.o
	ar rcs libkdump.a libkdump.o 

install: libkdump.a libkdump.so
	cp libkdump.so /usr/local/lib
	cp libkdump.h /usr/local/include
	ldconfig
	
uninstall: 
	rm /usr/local/lib/libkdump.so
	rm /usr/local/include/libkdump.h
	ldconfig
	
clean:
	rm -f *.o *.so *.a
