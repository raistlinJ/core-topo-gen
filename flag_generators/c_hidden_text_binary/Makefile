OUT_DIR ?= out
BIN := $(OUT_DIR)/hiddenbin

.PHONY: all clean

all: $(BIN)

$(OUT_DIR):
	mkdir -p "$(OUT_DIR)"

generated.h:
	@set -eu; \
	if [ -z "$${TEXT:-}" ] && [ -z "$${SEED:-}" ]; then \
		echo "Missing TEXT or SEED" >&2; \
		exit 2; \
	fi; \
	if [ -n "$${TEXT:-}" ]; then \
		val="$${TEXT}"; \
	else \
		n=$$(printf "%s" "$${SEED}" | cksum | awk '{print $$1}'); \
		a=$$((n % 256)); \
		b=$$(((n / 256) % 256)); \
		c=$$(((n / 65536) % 256)); \
		d=$$(((n / 16777216) % 256)); \
		val="10.$$a.$$b.$$c-$$d"; \
	fi; \
	# escape backslashes and double-quotes for a C string literal
	esc=$$(printf "%s" "$$val" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g'); \
	printf '#define HIDDEN_TEXT "%s"\n' "$$esc" > generated.h

$(BIN): main.c generated.h | $(OUT_DIR)
	cc -O2 -o "$(BIN)" main.c

clean:
	rm -rf "$(OUT_DIR)" generated.h
