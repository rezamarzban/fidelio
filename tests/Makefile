# Host-side regression test for the CTAP2 COSE_Key wire format.
#
# Fidelio used to encode and parse COSE_Key maps by hand; that code is now
# wolfCOSE. Every credential already registered with a device depends on the
# encoding not changing, so this test pins it: it compares wolfCOSE's output
# byte-for-byte against the original hand-rolled encoder, checks the exact
# CTAP2 canonical layout, and asserts that encoding from a key which still
# holds its private scalar never serialises that scalar.
#
#   make -C tests run

TOP      := $(CURDIR)/..
WOLFSSL  := $(TOP)/lib/wolfssl
WOLFCOSE := $(TOP)/lib/wolfcose

CC      ?= gcc
CFLAGS  := -O1 -Wall -DWOLFSSL_USER_SETTINGS -DNO_PWDBASED -DNO_PKCS8 \
           -DNO_PKCS12 -I$(CURDIR) -I$(WOLFSSL) -I$(WOLFCOSE)/include

WC_SRC  := ecc sp_c32 sp_int wolfmath memory misc random hash sha256 hmac \
           error logging wc_port asn coding kdf aes
SRC     := cose_wire_test.c \
           $(WOLFCOSE)/src/wolfcose.c $(WOLFCOSE)/src/wolfcose_cbor.c \
           $(patsubst %,$(WOLFSSL)/wolfcrypt/src/%.c,$(WC_SRC))

all: cose_wire_test

cose_wire_test: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

run: cose_wire_test
	./cose_wire_test
	$(MAKE) att_test

# att_test: the per-device attestation key and the on-device certificate
# (src/att.c). Needs a host wolfSSL with certificate generation: a build with
# --enable-certgen --enable-certext plus -DWOLFSSL_EKU_OID
# -DHAVE_OID_ENCODING. Skipped when absent. The C side checks determinism,
# per-device uniqueness, caching and the rebuild after a secret rotation;
# the openssl pass says the DER is a real certificate and that its public
# key is the one att_key_init derives.
CG_SRC   ?= /tmp/wolfssl-certgen

att_test:
	@if [ -f "$(CG_SRC)/src/.libs/libwolfssl.a" ]; then \
		TMP=$$(mktemp -d); \
		cp $(TOP)/src/att.c $(TOP)/src/att.h $$TMP/; \
		printf '#ifndef DEVICE_STATE_H\n#define DEVICE_STATE_H\n#include <stdint.h>\nconst uint8_t *device_get_secret(void);\n#endif\n' > $$TMP/device_state.h; \
		$(CC) -Wall -Wextra -DWOLFSSL_USE_OPTIONS_H -DForceZero=wc_ForceZero \
			-I"$(CG_SRC)" -I$$TMP att_test.c $$TMP/att.c \
			"$(CG_SRC)/src/.libs/libwolfssl.a" -o $$TMP/att_test; \
		(cd $$TMP && ./att_test); \
		for c in att_test_cert att_test_cert_rotated; do \
			openssl x509 -in $$TMP/$$c.der -inform der -out $$TMP/$$c.pem; \
			openssl verify -check_ss_sig -CAfile $$TMP/$$c.pem $$TMP/$$c.pem > /dev/null; \
			openssl x509 -in $$TMP/$$c.pem -noout -pubkey | \
				openssl ec -pubin -outform der -conv_form uncompressed 2>/dev/null | \
				tail -c 65 > $$TMP/$$c.pub; \
			case "$$c" in \
				*_rotated) want=$$TMP/att_test_pub_rotated.bin ;; \
				*)         want=$$TMP/att_test_pub.bin ;; \
			esac; \
			cmp $$TMP/$$c.pub $$want; \
		done; \
		rm -rf $$TMP; \
		echo "att_test: certificates parse, self-signatures verify, keys match"; \
	else \
		echo "att_test: SKIPPED (no certgen host wolfSSL at $(CG_SRC); set WOLFSSL_CERTGEN_SRC)"; \
	fi

clean:
	rm -f cose_wire_test

.PHONY: all run clean att_test
