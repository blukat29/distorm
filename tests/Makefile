CFLAGS = -Wall
LDFLAGS = -L../make/linux -L../make/mac -ldistorm3
BIN = disasm

all: $(BIN)

$(BIN): main.c
	gcc $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)
