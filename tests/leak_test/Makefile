# Host-side regression test for the CTAPHID stack leak (issue #10).
# Compiles the real src/u2f.c against stubbed pico/wolfssl headers and
# checks every HID frame the leak paths used to emit, byte-for-byte.
#
#   make -C tests/leak_test run

TOP      := $(CURDIR)/../..
CC       ?= gcc
CFLAGS   := -O1 -Wall -Wextra -std=c11 \
            -DFIDELIO_BOARD_PICO \
            -I$(CURDIR)/stubs -I$(TOP)/src

SRC      := leak_test.c stubs.c $(TOP)/src/u2f.c

all: leak_test

leak_test: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: leak_test
	./leak_test

clean:
	rm -f leak_test

.PHONY: all run clean
