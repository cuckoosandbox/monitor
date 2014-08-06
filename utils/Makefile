CC32 = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -s -static

UTILSRC = $(wildcard *.c)
UTILEXE = $(UTILSRC:%.c=%-x86.exe) $(UTILSRC:%.c=%-x64.exe)

default: $(UTILEXE)

%-x86.exe: %.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -m32

%-x64.exe: %.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -m64

clean:
	rm -f $(TOOLS)
