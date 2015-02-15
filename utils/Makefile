CC32 = i686-w64-mingw32-gcc -m32
CC64 = x86_64-w64-mingw32-gcc -m64
CFLAGS = -Wall -Wextra -O2 -std=c99 -s -static

UTILSRC = $(wildcard *.c)
UTILEXE = $(UTILSRC:%.c=%-x86.exe) $(UTILSRC:%.c=%-x64.exe)

default: $(UTILEXE)

dllinject-x86.exe: dllinject.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) ../src/assembly.c

dllinject-x64.exe: dllinject.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) ../src/assembly.c

clean:
	rm -f $(UTILEXE)
