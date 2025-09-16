CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -g
TARGET=tcp_ip_stack
SOURCES=main.c tcp_ip_stack.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run