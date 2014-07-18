CC = i686-w64-mingw32-gcc
NASM = nasm
CFLAGS = -m32 -Wall -O2 -Wextra -std=c99 -s -static
LDFLAGS = -lws2_32 -lshlwapi
INC = -I src/ -I objects/code/

SIGS = $(wildcard sigs/*.rst)
HOOK = objects/code/hooks.h objects/code/hooks.c \
	   objects/code/explain.c objects/code/tables.c
HOOKOBJ = objects/code/hooks.o objects/code/explain.o objects/code/tables.o

SRC = $(wildcard src/*.c)
SRCOBJ = $(SRC:%.c=objects/%.o)

ASM = $(wildcard asm/*.asm)
ASMOBJ = $(ASM:%.asm=objects/%.o)

BSON = $(wildcard src/bson/*.c)
BSONOBJ = $(BSON:%.c=objects/%.o)
LIBBSON = objects/src/libbson.a

LIBCAPSTONE = src/capstone/capstone.lib

DLL = monitor.dll

all: dirs $(HOOK) $(DLL)

dirs:
	mkdir -p objects/asm/ objects/code/ objects/src/ objects/src/bson/

$(HOOK): $(SIGS) process.py
	python process.py data/ objects/code/ $(SIGS)

objects/src/bson/%.o: src/bson/%.c

$(LIBBSON): $(BSONOBJ)
	$(AR) cr $@ $^

$(LIBCAPSTONE):
	git submodule update --init && \
	cp data/capstone-config.mk src/capstone/config.mk && \
	cd src/capstone/ && ./make.sh cross-win32

objects/src/%.o: src/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

objects/code/%.o: objects/code/%.c
	$(CC) -c -o $@ $^ $(CFLAGS) $(INC)

objects/asm/%.o: asm/%.asm
	$(NASM) -f elf32 -o $@ $^

$(DLL): $(ASMOBJ) $(SRCOBJ) $(HOOKOBJ) $(LIBBSON) $(LIBCAPSTONE)
	$(CC) -shared -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(HOOK) $(HOOKOBJ) $(BSONOBJ) $(SRCOBJ) $(ASMOBJ) $(DLL)
