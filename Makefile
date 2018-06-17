CC32 = i686-w64-mingw32-gcc -m32
CC64 = x86_64-w64-mingw32-gcc -m64
AR = ar
CFLAGS = -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers \
		 -I inc/ -I objects/code/ -I src/bson/ -I src/sha1/ -mwindows
LDFLAGS = -lshlwapi
MAKEFLAGS = -j8

SIGS = $(wildcard sigs/*.rst)
FLAGS = $(wildcard flags/*.rst)
JINJA2 = $(wildcard data/*.jinja2)
YAML = $(wildcard insn/*.yml)

# Dependencies for the auto-generated hook files.
HOOKREQ = utils/process.py $(wildcard data/*.json) $(wildcard data/*.conf)

# HOOKSRC only contains one element as the related auto-generated files are
# automatically created as well (if not emitting them it'll re-generate *all*
# the to-be-auto-generated files multiple times).
HOOKSRC = objects/code/hooks.c
HOOKOBJ32 = objects/x86/code/hooks.o
HOOKOBJ64 = objects/x64/code/hooks.o
FLAGSRC = objects/code/flags.c
FLAGOBJ32 = objects/x86/code/flags.o
FLAGOBJ64 = objects/x64/code/flags.o
INSNSSRC = objects/code/insns.c
INSNSOBJ32 = objects/x86/code/insns.o
INSNSOBJ64 = objects/x64/code/insns.o

SRC = $(wildcard src/*.c)
SRCOBJ32 = $(SRC:%.c=objects/x86/%.o)
SRCOBJ64 = $(SRC:%.c=objects/x64/%.o)
HEADER = $(wildcard inc/*.h)

BSON = $(wildcard src/bson/*.c)
BSONOBJ32 = $(BSON:%.c=objects/x86/%.o)
BSONOBJ64 = $(BSON:%.c=objects/x64/%.o)

SHA1 = src/sha1/sha1.c
SHA1OBJ32 = objects/x86/src/sha1/sha1.o
SHA1OBJ64 = objects/x64/src/sha1/sha1.o

LIBCAPSTONE32 = src/capstone/capstone-x86.lib
LIBCAPSTONE64 = src/capstone/capstone-x64.lib

BINARIES = \
	bin/inject-x86.exe bin/inject-x64.exe bin/is32bit.exe \
	bin/monitor-x86.dll bin/monitor-x64.dll

ifdef DEBUG
	CFLAGS += -DDEBUG=1 -O0 -ggdb
	RELMODE = debug
else
	CFLAGS += -DDEBUG=0 -O0 -s
	RELMODE = release
endif

ifdef DEBUG_STANDALONE
	CFLAGS += -DDEBUG_STANDALONE=1
endif

all: $(BINARIES)

$(HOOKSRC): $(SIGS) $(FLAGS) $(JINJA2) $(HOOKREQ) $(YAML)
	python2 utils/process.py $(RELMODE) --apis=$(APIS)

$(INSNSSRC) $(FLAGSRC): $(HOOKSRC)

$(LIBCAPSTONE32):
	cd src/capstone/ && \
	CAPSTONE_ARCHS="x86" BUILDDIR=../../objects/x86/capstone/ ./make.sh cross-win32 && \
	cp ../../objects/x86/capstone/capstone.lib capstone-x86.lib

$(LIBCAPSTONE64):
	cd src/capstone/ && \
	CAPSTONE_ARCHS="x86" BUILDDIR=../../objects/x64/capstone/ ./make.sh cross-win64 && \
	cp ../../objects/x64/capstone/capstone.lib capstone-x64.lib

objects/x86/%.o: %.c $(HEADER) Makefile
	$(CC32) -c -o $@ $< $(CFLAGS)

objects/x86/%.o: objects/x86/%.c $(HEADER) $(HOOKSRC) Makefile
	$(CC32) -c -o $@ $< $(CFLAGS)

objects/x64/%.o: %.c $(HEADER) Makefile
	$(CC64) -c -o $@ $< $(CFLAGS)

objects/x64/%.o: objects/x64/%.c $(HEADER) $(HOOKSRC) Makefile
	$(CC64) -c -o $@ $< $(CFLAGS)

$(HOOKOBJ32): $(HOOKSRC) $(HEADER) Makefile
	$(CC32) -c -o $@ $< $(CFLAGS)

$(HOOKOBJ64): $(HOOKSRC) $(HEADER) Makefile
	$(CC64) -c -o $@ $< $(CFLAGS)

$(FLAGOBJ32): $(FLAGSRC) $(HEADER) Makefile
	$(CC32) -c -o $@ $< $(CFLAGS)

$(FLAGOBJ64): $(FLAGSRC) $(HEADER) Makefile
	$(CC64) -c -o $@ $< $(CFLAGS)

$(INSNSOBJ32): $(INSNSSRC) $(HEADER) Makefile
	$(CC32) -c -o $@ $< $(CFLAGS)

$(INSNSOBJ64): $(INSNSSRC) $(HEADER) Makefile
	$(CC64) -c -o $@ $< $(CFLAGS)

bin/monitor-x86.dll: bin/monitor.c $(SRCOBJ32) $(HOOKOBJ32) $(FLAGOBJ32) \
		$(INSNSOBJ32) $(BSONOBJ32) $(LIBCAPSTONE32) $(SHA1OBJ32)
	$(CC32) -shared -o $@ $^ $(CFLAGS) $(LDFLAGS)

bin/monitor-x64.dll: bin/monitor.c $(SRCOBJ64) $(HOOKOBJ64) $(FLAGOBJ64) \
		$(INSNSOBJ64) $(BSONOBJ64) $(LIBCAPSTONE64) $(SHA1OBJ64)
	$(CC64) -shared -o $@ $^ $(CFLAGS) $(LDFLAGS)

bin/inject-x86.exe: bin/inject.c src/assembly.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -I inc

bin/inject-x64.exe: bin/inject.c src/assembly.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -I inc

bin/is32bit.exe: bin/is32bit.c
	$(CC32) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(HOOKSRC) $(HOOKOBJ32) $(HOOKOBJ64) $(FLAGSRC) $(FLAGOBJ32)
	rm -rf $(FLAGOBJ64) $(INSNSSRC) $(INSNSOBJ32) $(INSNSOBJ64) $(SRCOBJ32)
	rm -rf $(SRCOBJ64) $(BSONOBJ32) $(BSONOBJ64) $(SHA1OBJ32) $(SHA1OBJ64)
	rm -rf $(BINARIES)

clean-capstone:
	rm -rf $(LIBCAPSTONE32) $(LIBCAPSTONE64)
