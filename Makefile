CC = i686-w64-mingw32-gcc
CFLAGS = -m32 -Wall -O2 -Wextra -std=c99

SIGS = $(wildcard sigs/*.rst)
HOOKS =_hooks.h _hooks.c
SRC = $(wildcard *.c)
DLL = monitor.dll

all: $(HOOKS) $(DLL)

$(HOOKS): $(SIGS) process.py
	python process.py _hooks.h _hooks.c $(SIGS)

$(DLL): $(HOOKS) $(SRC)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(HOOKS) $(DLL)
