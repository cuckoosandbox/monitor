CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -m32 -s -static

TOOLS = dllinject.exe

default: $(TOOLS)

%.exe: %.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(TOOLS)
