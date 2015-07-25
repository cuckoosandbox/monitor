CC32 = i686-w64-mingw32-gcc -m32
CC64 = x86_64-w64-mingw32-gcc -m64
CFLAGS = -Wall -Wextra -O2 -std=c99 -static -s -mwindows
LDFLAGS = -lshlwapi

UTILSRC = $(wildcard *.c)
UTILEXE = helloworld-x86.dll helloworld-x64.dll

default: $(UTILEXE)

helloworld-x86.dll: helloworld.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -shared

helloworld-x64.dll: helloworld.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -shared

clean:
	rm -f $(UTILEXE)
