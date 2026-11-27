
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g

TARGET = tcp_ip_stack
CLI_TARGET = packet_cli
SANITIZER_TARGET = tcp_ip_stack_sanitized

SOURCES = main.c tcp_ip_stack.c
CLI_SOURCES = packet_cli.c tcp_ip_stack.c
HEADERS = tcp_ip_stack.h

.PHONY: all run test cli sanitize clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

$(CLI_TARGET): $(CLI_SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(CLI_SOURCES) -o $(CLI_TARGET)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./$(TARGET)

cli: $(CLI_TARGET)

sanitize: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer $(SOURCES) -o $(SANITIZER_TARGET)
	./$(SANITIZER_TARGET)

clean:
	rm -f $(TARGET) $(CLI_TARGET) $(SANITIZER_TARGET) *.o
