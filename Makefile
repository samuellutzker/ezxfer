CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wno-overlength-strings
BUILD   := build

SRCS    := src/main.c src/server.c src/proto.c src/sha1.c src/qr.c
LIBSRCS := src/proto.c src/sha1.c src/qr.c

.PHONY: all clean test test-unit test-qr test-integration test-e2e

all: ezxfer

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/embed: tools/embed.c | $(BUILD)
	$(CC) -O2 -o $@ $<

$(BUILD)/index_html.h: web/index.html $(BUILD)/embed
	$(BUILD)/embed $< index_html > $@

ezxfer: $(SRCS) src/*.h $(BUILD)/index_html.h
	$(CC) $(CFLAGS) -I$(BUILD) -o $@ $(SRCS) $(LDFLAGS)

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

test-e2e: ezxfer
	node tests/e2e.mjs ./ezxfer

test: test-unit test-qr test-integration test-e2e

clean:
	rm -rf $(BUILD) ezxfer
