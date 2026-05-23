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

# Shellcode targets
SC_CFLAGS  := -Os -fPIC -nostdlib -nostartfiles -ffreestanding \
              -fno-asynchronous-unwind-tables -fno-ident -e start -s \
              -mno-stack-arg-probe -std=c11 -Wall -Wextra
SC_OBJCOPY := x86_64-w64-mingw32-objcopy -O binary

MINIPLASMA_SC_SRC    := src/miniplasma_sc.c
MINIPLASMA_SC_OBJ    := $(BUILD)/miniplasma_sc.o
MINIPLASMA_SC_BIN    := $(BUILD)/miniplasma_sc.bin
MINIPLASMA_SC_HEADER := src/miniplasma_sc_data.h

MINIRUNNER_SC_SRC := src/mini_runner_sc.c
MINIRUNNER_SC_OBJ := $(BUILD)/mini_runner_sc.o
MINIRUNNER_SC_BIN := $(BUILD)/mini_runner_sc.bin

.PHONY: all clean miniplasma shellcode run_ps1

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

shellcode: $(MINIRUNNER_SC_BIN) $(MINIPLASMA_SC_BIN)

$(MINIRUNNER_SC_OBJ): $(MINIRUNNER_SC_SRC) | $(BUILD)
	$(CC) $(SC_CFLAGS) -c $< -o $@

$(MINIRUNNER_SC_BIN): $(MINIRUNNER_SC_OBJ)
	$(SC_OBJCOPY) $< $@

$(MINIPLASMA_SC_OBJ): $(MINIPLASMA_SC_SRC) $(MINIPLASMA_SC_HEADER) | $(BUILD)
	$(CC) $(SC_CFLAGS) -c $< -o $@

$(MINIPLASMA_SC_BIN): $(MINIPLASMA_SC_OBJ)
	$(SC_OBJCOPY) $< $@

# Regenerate the data header from mini_runner_sc shellcode
$(MINIPLASMA_SC_HEADER): $(MINIRUNNER_SC_BIN)
	xxd -i $(MINIRUNNER_SC_BIN) | sed '1s/.*/__attribute__((section(".text"))) static const unsigned char runner_pe_data[] = {/' | sed '$$d' > $@

$(BUILD)/run_miniplasma.ps1: $(MINIPLASMA_SC_BIN) tools/run_sc.ps1 tools/embed_sc.py
	python3 tools/embed_sc.py tools/run_sc.ps1 $(MINIPLASMA_SC_BIN) $@

run_ps1: $(BUILD)/run_miniplasma.ps1

clean:
	rm -rf $(BUILD) $(MINIRUNNER_HEADER) $(MINIPLASMA_SC_HEADER)
