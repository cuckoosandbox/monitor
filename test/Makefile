CC32 = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O0 -ggdb -Wextra -std=c99 -s -static \
		 -Wno-missing-field-initializers -I ../inc -I objects/code/
LDFLAGS = -lws2_32 -lshlwapi -lcrypt32

TESTSRC = $(wildcard *.c)
TESTEXE = $(TESTSRC:%.c=%-x86.exe) $(TESTSRC:%.c=%-x64.exe)

all: $(TESTEXE)

%-x86.exe: %.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -m32

%-x64.exe: %.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -m64

clean:
	rm -rf $(TESTEXE)
