# Builds the TURN UDC2 BOF for Cobalt Strike (x64 and x86) using
# mingw-w64. Works on Linux/macOS (brew install mingw-w64) and Windows
# (via MSYS2); MSVC users can also drop the sources into the official
# udc2-vs template solution.
#
# Before building, generate bof_config.h with live values:
#   turn-udc2-server --emit-bof-config bof/bof_config.h
# or edit the defaults in bof_config.h / override with -D flags.

CC_X64 := x86_64-w64-mingw32-gcc
CC_X86 := i686-w64-mingw32-gcc
LD_X64 := x86_64-w64-mingw32-ld
LD_X86 := i686-w64-mingw32-ld

CFLAGS := -std=c11 -Os -Wall -Wextra -Wno-unused-parameter \
          -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables

.DEFAULT_GOAL := all

SRCS := crypto.c stun.c schannel.c msteams.c turn.c proto.c turn_udc2_bof.c
X64_OBJS := $(SRCS:.c=.x64.o)
X86_OBJS := $(SRCS:.c=.x86.o)

HEADERS := bof_config.h dfr.h udc2.h crypto.h stun.h schannel.h msteams.h turn.h proto.h

# Use the generated config when present; otherwise fall back to the
# template (with placeholder credentials) so the tree builds out of the
# box. `turn-udc2-server --emit-bof-config bof/bof_config.h` wins.
bof_config.h: bof_config.h.example
	cp $< $@
	@echo "note: using template bof_config.h (placeholders); run turn-udc2-server --emit-bof-config bof/bof_config.h for live values"

all: turn_udc2.x64.o turn_udc2.x86.o

# Windows x64 test harness: runs the exact BOF objects outside Beacon
# (mini BOF loader + console main). Link with the CRT like a normal exe;
# the BOF's own imports are resolved through debug/loader.c.
# Debug objects are built into separate .debug.o files so they never
# pollute the production BOF objects.
DEBUG_OBJS := crypto.debug.x64.o stun.debug.x64.o schannel.debug.x64.o msteams.debug.x64.o turn.debug.x64.o proto.debug.x64.o turn_udc2_bof.debug.x64.o

turn_udc2_test.exe: debug/loader.c debug/main.c $(DEBUG_OBJS)
	$(CC_X64) -O2 -o $@ debug/loader.c debug/main.c $(DEBUG_OBJS)
	@echo "== $@ built (copy to a Windows x64 box and run against a live server + fakets) =="

debug: turn_udc2_test.exe

%.debug.x64.o: %.c $(HEADERS)
	$(CC_X64) $(CFLAGS) -DTURN_DEBUG -c -o $@ $<

%.x64.o: %.c $(HEADERS)
	$(CC_X64) $(CFLAGS) -c -o $@ $<

%.x86.o: %.c $(HEADERS)
	$(CC_X86) $(CFLAGS) -c -o $@ $<

turn_udc2.x64.o: $(X64_OBJS)
	$(LD_X64) -r -o $@ $(X64_OBJS)
	@echo "== $@: `stat -f%z $@ 2>/dev/null || stat -c%s $@` bytes (BOF limit ~32KB) =="

turn_udc2.x86.o: $(X86_OBJS)
	$(LD_X86) -r -o $@ $(X86_OBJS)
	@echo "== $@: `stat -f%z $@ 2>/dev/null || stat -c%s $@` bytes (BOF limit ~32KB) =="

clean:
	rm -f *.x64.o *.x86.o *.debug.x64.o turn_udc2.x64.o turn_udc2.x86.o bof_config.h turn_udc2_test.exe

.PHONY: all clean debug
