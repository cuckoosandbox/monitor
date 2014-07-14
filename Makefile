CC = i686-w64-mingw32-gcc
NASM = nasm
CFLAGS = -m32 -Wall -O2 -Wextra -std=c99 -s
INC = -I src/ -I objects/code/

SIGS = $(wildcard sigs/*.rst)
HOOK = objects/code/hooks.h objects/code/hooks.c
HOOKOBJ = objects/code/hooks.o
SRC = $(wildcard src/*.c)
SRCOBJ = $(SRC:%.c=objects/%.o)
ASM = $(wildcard asm/*.asm)
ASMOBJ = $(ASM:%.asm=objects/%.o)
DLL = monitor.dll

all: dirs $(HOOK) $(DLL)

dirs:
	mkdir -p objects/asm objects/code objects/src

$(HOOK): $(SIGS) process.py
	python process.py objects/code/hooks.h objects/code/hooks.c $(SIGS)

objects/src/%.o: src/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

objects/code/%.o: objects/code/%.c
	$(CC) -c -o $@ $^ $(CFLAGS) $(INC)

objects/asm/%.o: asm/%.asm
	$(NASM) -f elf32 -o $@ $^

$(DLL): $(HOOKOBJ) $(ASMOBJ) $(SRCOBJ)
	$(CC) -shared -o $@ $^ $(CFLAGS)

clean:
	rm -f $(HOOKS) $(SRCOBJ) $(ASMOBJ) $(DLL)
