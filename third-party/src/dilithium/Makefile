CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mpopcnt -maes \
  -march=native -mtune=native -O3
SOURCES = sign.c packing.c polyvec.c poly.c ntt.S invntt.S pointwise.S \
  shuffle.S consts.c rejsample.c rounding.c
HEADERS = align.h config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  consts.h shuffle.inc rejsample.h rounding.h symmetric.h randombytes.h
KECCAK_SOURCES = $(SOURCES) fips202.c fips202x4.c f1600x4.S symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h fips202x4.h
AES_SOURCES = $(SOURCES) fips202.c aes256ctr.c
AES_HEADERS = $(HEADERS) fips202.h aes256ctr.h

.PHONY: all shared clean

shared: \
  libpqcrystals_dilithium2aes_avx2.so

libpqcrystals_dilithium2aes_avx2.so: $(SOURCES) $(HEADERS)
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES)

clean:
	rm -f *.o *.a *.so
