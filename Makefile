CC = x86_64-w64-mingw32-gcc
CFLAGS = -m64 -Wl,--dynamicbase
LDFLAGS = -lpsapi -ldbghelp -lntdll
TARGET = ClipboardHistoryThief.exe
SOURCE = ClipboardHistoryThief.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)