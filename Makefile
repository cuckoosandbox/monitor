CC = i686-w64-mingw32-gcc
CFLAGS = -m32 -Wall -O2 -Wextra

SIGS = $(wildcard sigs/*.rst)

_hooks.h _hooks.c: $(SIGS)
	python process.py _hooks.h _hooks.c $^

clean:
	rm -f _hooks.h _hooks.c
