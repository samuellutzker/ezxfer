CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wno-overlength-strings
BUILD   := build

SRCS    := src/main.c src/server.c src/tls.c src/proto.c src/sha1.c src/qr.c

# TLS (HTTPS) support via OpenSSL: auto-detected with pkg-config.
# Force with `make TLS=1`, or build the dependency-free binary with `make TLS=0`.
TLS     ?= $(shell pkg-config --exists openssl 2>/dev/null && echo 1 || echo 0)
ifeq ($(TLS),1)
  TLS_CFLAGS := -DEZX_TLS $(shell pkg-config --cflags openssl 2>/dev/null)
  TLS_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)
endif
LIBSRCS := src/proto.c src/sha1.c src/qr.c

.PHONY: all clean test test-unit test-qr test-integration test-integration-tls test-e2e test-e2e-tls

all: ezxfer

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/embed: tools/embed.c | $(BUILD)
	$(CC) -O2 -o $@ $<

$(BUILD)/index_html.h: web/index.html $(BUILD)/embed
	$(BUILD)/embed $< index_html > $@

$(BUILD)/sw_js.h: web/sw.js $(BUILD)/embed
	$(BUILD)/embed $< sw_js > $@

ezxfer: $(SRCS) src/*.h $(BUILD)/index_html.h $(BUILD)/sw_js.h $(BUILD)/tls-$(TLS)
	$(CC) $(CFLAGS) $(TLS_CFLAGS) -I$(BUILD) -o $@ $(SRCS) $(LDFLAGS) $(TLS_LIBS)

# rebuild when switching between TLS=0 and TLS=1
$(BUILD)/tls-$(TLS): | $(BUILD)
	rm -f $(BUILD)/tls-*
	touch $@

$(BUILD)/test_unit: tests/test_unit.c $(LIBSRCS) src/*.h | $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc -o $@ tests/test_unit.c $(LIBSRCS)

$(BUILD)/qrgen: tests/qrgen.c $(LIBSRCS) src/*.h | $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -O2 -Isrc -o $@ tests/qrgen.c $(LIBSRCS)

test-unit: $(BUILD)/test_unit
	$(BUILD)/test_unit

# needs: pip install qrcode; (cd tests && npm install) for the jsQR decode check
test-qr: $(BUILD)/qrgen
	python3 tests/test_qr_reference.py $(BUILD)/qrgen tests/qr_decode.cjs

test-integration: ezxfer
	python3 tests/test_integration.py ./ezxfer

test-integration-tls: ezxfer
	python3 tests/test_integration.py ./ezxfer --tls

test-e2e: ezxfer
	node tests/e2e.mjs ./ezxfer

test-e2e-tls: ezxfer
	node tests/e2e.mjs ./ezxfer --tls

test: test-unit test-qr test-integration test-e2e $(if $(filter 1,$(TLS)),test-integration-tls test-e2e-tls)

clean:
	rm -rf $(BUILD) ezxfer
