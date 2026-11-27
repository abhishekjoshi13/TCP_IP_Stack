
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tcp_ip_stack.h"

#define MAX_FRAME_SIZE 65549
#define MAX_INPUT_SIZE (MAX_FRAME_SIZE * 2 + 2)

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static int decode_hex(
    const char* input,
    unsigned char* output,
    size_t* output_length
) {
    int high = -1;
    size_t count = 0;

    for (size_t i = 0; input[i] != '\0'; i++) {
        unsigned char c = (unsigned char)input[i];

        if (isspace(c) || c == ':') {
            continue;
        }

        int value = hex_value((char)c);

        if (value < 0) {
            return 0;
        }

        if (high < 0) {
            high = value;
        } else {
            if (count >= MAX_FRAME_SIZE) {
                return 0;
            }

            output[count++] =
                (unsigned char)((high << 4) | value);

            high = -1;
        }
    }

    if (high >= 0 || count == 0) {
        return 0;
    }

    *output_length = count;
    return 1;
}

int main(int argc, char* argv[]) {
    const char* local_address = "192.168.1.1";

    if (argc > 2) {
        fprintf(stderr, "Usage: packet_cli [local_ipv4]\n");
        return 1;
    }

    if (argc == 2) {
        local_address = argv[1];
    }

    if (parse_ipv4(local_address) == 0) {
        fprintf(stderr, "Invalid local IPv4 address.\n");
        return 1;
    }

    char* input = malloc(MAX_INPUT_SIZE);

    if (input == NULL) {
        fprintf(stderr, "Unable to allocate input buffer.\n");
        return 1;
    }

    unsigned char* frame = malloc(MAX_FRAME_SIZE);

    if (frame == NULL) {
        fprintf(stderr, "Unable to allocate packet buffer.\n");
        free(input);
        return 1;
    }

    if (fgets(input, MAX_INPUT_SIZE, stdin) == NULL) {
        fprintf(stderr, "No packet input received.\n");
        free(frame);
        free(input);
        return 1;
    }

    size_t frame_length = 0;

    if (!decode_hex(input, frame, &frame_length)) {
        fprintf(stderr, "Invalid or oversized hexadecimal packet.\n");
        free(frame);
        free(input);
        return 1;
    }

    network_init(local_address);

    printf("\n=== C Packet Processing Engine ===\n");
    printf("Received frame: %zu bytes\n", frame_length);

    process_frame(frame, frame_length);

    printf("FRAME_SUBMITTED bytes=%zu\n", frame_length);

    free(frame);
    free(input);

    return 0;
}
