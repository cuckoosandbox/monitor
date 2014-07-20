CC = i686-w64-mingw32-gcc
NASM = nasm
AR = ar
CFLAGS = -m32 -Wall -O0 -ggdb -Wextra -std=c99 -static \
		 -Wno-missing-field-initializers -I src/ -I objects/code/
LDFLAGS = -lws2_32 -lshlwapi

SIGS = $(wildcard sigs/*.rst)
HOOK = objects/code/hooks.h objects/code/hooks.c \
	   objects/code/explain.c objects/code/tables.c
HOOKOBJ = objects/code/hooks.o objects/code/explain.o objects/code/tables.o

SRC = $(wildcard src/*.c)
SRCOBJ = $(SRC:%.c=objects/%.o)
HEADER = $(wildcard src/*.h)

ASM = $(wildcard asm/*.asm)
ASMOBJ = $(ASM:%.asm=objects/%.o)

BSON = $(wildcard src/bson/*.c)
BSONOBJ = $(BSON:%.c=objects/%.o)
LIBBSON = objects/src/libbson.a

LIBCAPSTONE = src/capstone/capstone.lib

DLL = monitor.dll

all: dirs $(HOOK) $(DLL)

dirs: | objects/

objects/:
	mkdir -p objects/asm/ objects/code/ objects/src/ objects/src/bson/

$(HOOK): $(SIGS) scripts/process.py
	python scripts/process.py data/ objects/code/ $(SIGS)

objects/src/bson/%.o: src/bson/%.c

$(LIBBSON): $(BSONOBJ)
	$(AR) cr $@ $^

$(LIBCAPSTONE):
	git submodule update --init && \
	cp data/capstone-config.mk src/capstone/config.mk && \
	cd src/capstone/ && ./make.sh cross-win32

objects/src/%.o: src/%.c $(HEADER)
	$(CC) -c -o $@ $< $(CFLAGS)

objects/code/%.o: objects/code/%.c $(HEADER)
	$(CC) -c -o $@ $< $(CFLAGS)

objects/asm/%.o: asm/%.asm
	$(NASM) -f elf32 -o $@ $^

$(DLL): $(ASMOBJ) $(SRCOBJ) $(HOOKOBJ) $(LIBBSON) $(LIBCAPSTONE)
	$(CC) -shared -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf objects/ $(DLL)
