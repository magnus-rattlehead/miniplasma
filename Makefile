CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -std=c11 -Wall -Wextra -O2

BUILD  := build
TARGET := $(BUILD)/miniplasma.exe
SRC    := src/miniplasma.c
HEADER := src/mini_runner_data.h

MINIRUNNER_BIN := $(BUILD)/mini_runner.exe
MINIRUNNER_SRC := src/mini_runner.c

# OS detection
H  := $(subst /,\\,$(HEADER))

ifeq ($(OS),Windows_NT)
  PYTHON    := python
  MKDIR_CMD := if not exist $(BUILD) mkdir $(BUILD)
  CLEAN_CMD := if exist $(BUILD) rmdir /s /q $(BUILD) & if exist $(H) del /f /q $(H)
else
  PYTHON    := python3
  MKDIR_CMD := mkdir -p $(BUILD)
  CLEAN_CMD := rm -rf $(BUILD) $(HEADER)
endif

.PHONY: all clean miniplasma

all: $(TARGET)

$(TARGET): $(SRC) $(HEADER) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ -mconsole -static -static-libgcc -lole32 -loleaut32 -lrpcrt4 -lntdll

$(MINIRUNNER_BIN): $(MINIRUNNER_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -Os -s -nostartfiles -e entry \
	  -fno-asynchronous-unwind-tables \
	  $< -o $@ -lkernel32 -lntdll -ladvapi32

$(HEADER): $(MINIRUNNER_BIN)
	$(PYTHON) tools/xor.py $(MINIRUNNER_BIN) $(MINIRUNNER_BIN).packed
	xxd -i -n build_mini_runner_exe_packed $(MINIRUNNER_BIN).packed > $(HEADER)

$(BUILD):
	$(MKDIR_CMD)

miniplasma: $(TARGET)

clean:
	$(CLEAN_CMD)
