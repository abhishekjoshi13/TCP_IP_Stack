CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -g
TARGET = tcp_ip_stack
SANITIZER_TARGET = tcp_ip_stack_sanitized
SOURCES = main.c tcp_ip_stack.c
HEADERS = tcp_ip_stack.h

.PHONY: all run test sanitize clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./$(TARGET)

sanitize: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer $(SOURCES) -o $(SANITIZER_TARGET)
	./$(SANITIZER_TARGET)

clean:
	rm -f $(TARGET) $(SANITIZER_TARGET) *.o
