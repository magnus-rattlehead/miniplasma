CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -std=c11 -Wall -Wextra -O2
LDFLAGS := -mconsole -static -static-libgcc -lole32 -loleaut32 -lrpcrt4 -lntdll

BUILD       := build
TARGET      := $(BUILD)/miniplasma.exe
SRC         := src/miniplasma.c
HEADER      := src/mini_runner_data.h

MINIRUNNER_BIN    := $(BUILD)/mini_runner.exe
MINIRUNNER_SRC    := src/mini_runner.c
MINIRUNNER_HEADER := src/mini_runner_data.h

.PHONY: all clean miniplasma

all: $(TARGET)

$(TARGET): $(SRC) $(MINIRUNNER_HEADER) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(MINIRUNNER_BIN): $(MINIRUNNER_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -Os -s -fno-asynchronous-unwind-tables \
	  $< -o $@ $(LDFLAGS)

$(MINIRUNNER_HEADER): $(MINIRUNNER_BIN)
	xxd -i $(MINIRUNNER_BIN) > $(MINIRUNNER_HEADER)

$(BUILD):
	mkdir -p $(BUILD)

miniplasma: $(TARGET)

clean:
	rm -rf $(BUILD) $(MINIRUNNER_HEADER)
