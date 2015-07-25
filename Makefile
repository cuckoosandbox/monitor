CC32 = i686-w64-mingw32-gcc -m32
CC64 = x86_64-w64-mingw32-gcc -m64
AR = ar
CFLAGS = -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers \
		 -I inc/ -I objects/code/ -I src/bson/
LDFLAGS = -lshlwapi
MAKEFLAGS = -j8

SIGS = $(wildcard sigs/*.rst)
JINJA2 = $(wildcard data/*.jinja2)

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

SRC = $(wildcard src/*.c)
SRCOBJ32 = $(SRC:%.c=objects/x86/%.o)
SRCOBJ64 = $(SRC:%.c=objects/x64/%.o)
HEADER = $(wildcard inc/*.h)

BSON = $(wildcard src/bson/*.c)
BSONOBJ32 = $(BSON:%.c=objects/x86/%.o)
BSONOBJ64 = $(BSON:%.c=objects/x64/%.o)

LIBCAPSTONE32 = src/capstone/capstone-x86.lib
LIBCAPSTONE64 = src/capstone/capstone-x64.lib

ifdef DEBUG
	CFLAGS += -DDEBUG=1 -O0 -ggdb
	RELMODE = debug
else
	CFLAGS += -DDEBUG=0 -O0 -s
	RELMODE = release
endif

all: dirs bin/inject-x86.exe bin/inject-x64.exe bin/is32bit.exe \
		bin/monitor-x86.dll bin/monitor-x64.dll

dirs: | objects/

objects/:
	mkdir -p objects/code/
	mkdir -p objects/x86/code/ objects/x64/code/
	mkdir -p objects/x86/src/bson/ objects/x64/src/bson/

$(HOOKSRC): $(SIGS) $(JINJA2) $(HOOKREQ)
	python utils/process.py $(RELMODE) --apis=$(APIS)

$(FLAGSRC): $(HOOKSRC)

src/capstone/config.mk:
	git submodule update --init
	cp data/capstone-config.mk src/capstone/config.mk

$(LIBCAPSTONE32): src/capstone/config.mk
	cd src/capstone/ && \
	BUILDDIR=../../objects/x86/capstone/ ./make.sh cross-win32 && \
	cp ../../objects/x86/capstone/capstone.lib capstone-x86.lib

$(LIBCAPSTONE64): src/capstone/config.mk
	cd src/capstone/ && \
	BUILDDIR=../../objects/x64/capstone/ ./make.sh cross-win64 && \
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

bin/monitor-x86.dll: $(SRCOBJ32) $(HOOKOBJ32) $(FLAGOBJ32) $(BSONOBJ32) $(LIBCAPSTONE32)
	$(CC32) -shared -o $@ bin/monitor.c $^ $(CFLAGS) $(LDFLAGS)

bin/monitor-x64.dll: $(SRCOBJ64) $(HOOKOBJ64) $(FLAGOBJ64) $(BSONOBJ64) $(LIBCAPSTONE64)
	$(CC64) -shared -o $@ bin/monitor.c $^ $(CFLAGS) $(LDFLAGS)

bin/inject-x86.exe: bin/inject.c src/assembly.c
	$(CC32) -o $@ $^ $(CFLAGS) $(LDFLAGS) -I inc

bin/inject-x64.exe: bin/inject.c src/assembly.c
	$(CC64) -o $@ $^ $(CFLAGS) $(LDFLAGS) -I inc

bin/is32bit.exe: bin/is32bit.c
	$(CC32) -o $@ $^ $(CFLAGS)

clean:
	rm -rf objects/ $(DLL32) $(DLL64)
	+make -C utils/ clean

clean-capstone:
	rm -rf $(LIBCAPSTONE32) $(LIBCAPSTONE64)
