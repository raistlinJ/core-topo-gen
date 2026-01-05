OUT_DIR ?= out
BIN := $(OUT_DIR)/basicbin

.PHONY: all clean

all: $(BIN)

$(OUT_DIR):
	mkdir -p "$(OUT_DIR)"

$(BIN): main.c | $(OUT_DIR)
	cc -O2 -o "$(BIN)" main.c

clean:
	rm -rf "$(OUT_DIR)"
