CC32 = i686-w64-mingw32-gcc -m32
CC64 = x86_64-w64-mingw32-gcc -m64
CFLAGS = -Wall -Wextra -O2 -std=c99 -static -s -mwindows
LDFLAGS = -lshlwapi

UTILSRC = $(wildcard *.c)
UTILEXE = inject-x86.exe inject-x64.exe \
		  helloworld-x86.dll helloworld-x64.dll \
		  is32bit.exe

default: $(UTILEXE)

inject-x86.exe: inject.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) ../src/assembly.c -I ../inc

inject-x64.exe: inject.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) ../src/assembly.c -I ../inc

helloworld-x86.dll: helloworld.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -shared

helloworld-x64.dll: helloworld.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -shared

is32bit.exe: is32bit.c
	$(CC32) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(UTILEXE)
