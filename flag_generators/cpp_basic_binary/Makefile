OUT_DIR ?= out
BIN := $(OUT_DIR)/basiccpp

.PHONY: all clean

all: $(BIN)

$(OUT_DIR):
	mkdir -p "$(OUT_DIR)"

$(BIN): main.cpp | $(OUT_DIR)
	c++ -O2 -std=c++17 -o "$(BIN)" main.cpp

clean:
	rm -rf "$(OUT_DIR)"
