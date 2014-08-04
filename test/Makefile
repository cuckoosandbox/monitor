CC = i686-w64-mingw32-gcc
CFLAGS = -m32 -Wall -O0 -ggdb -Wextra -std=c99 -s -static \
		 -Wno-missing-field-initializers -I ../inc -I objects/code/
LDFLAGS = -lws2_32 -lshlwapi

TESTSRC = $(wildcard *.c)
TESTEXE = $(TESTSRC:%.c=%.exe)

all: $(TESTEXE)

%.exe: %.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(TESTEXE)
