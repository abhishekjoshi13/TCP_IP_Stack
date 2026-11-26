
# TCP/IP Stack Testing Guide

This guide explains how to build and test the educational
TCP/IP stack implemented in C.

The project processes sample packets in memory. It does not
send packets over a real network interface.

## 1. Requirements

You need:

- GCC or a compatible C compiler
- GNU Make
- C99 support

For sanitizer testing, your compiler must also support
AddressSanitizer and UndefinedBehaviorSanitizer.

## 2. Build the Project

From the repository directory, run:

```bash
make
```

This compiles:

- `main.c`
- `tcp_ip_stack.c`

The resulting executable is:

```text
tcp_ip_stack
```

## 3. Run the Demonstration

Run:

```bash
make run
```

The program initializes the stack with:

```text
192.168.1.1
```

It then executes the built-in parser and checksum tests
and submits sample Ethernet frames to the packet processor.

## 4. Run the Built-in Tests

Run:

```bash
make test
```

### IPv4 Parser Tests

The current test program checks:

| Input | Expected result |
|---|---|
| `192.168.1.1` | Valid |
| `127.0.0.1` | Valid |
| `192.168.1.256` | Rejected |
| `192.168.1` | Rejected |
| `192.168.1.1abc` | Rejected |
| Null input | Rejected |

These cases use explicit pass/fail assertions.

### Checksum Tests

The checksum tests cover:

- Odd-length input.
- Validation of a packet containing its calculated checksum.
- Null input.
- Empty input.

These cases also use explicit pass/fail assertions.

## 5. Packet Processing Demonstrations

The program constructs and submits sample packets.

### ARP

A sample ARP request is constructed with:

- Ethernet frame header.
- Ethernet/IPv4 ARP header.
- Sender MAC and sender IP.
- Local destination IP.

The packet is submitted to `process_frame()`.

### ICMP

A sample IPv4 packet containing an ICMP echo request is
constructed.

The demonstration exercises:

- IPv4 header validation.
- IPv4 checksum verification.
- ICMP checksum verification.
- ICMP echo-request processing.
- Echo-reply preparation.

The reply is prepared in memory and is not transmitted.

### TCP

A sample IPv4 packet containing a TCP header and payload
is constructed.

The demonstration exercises:

- IPv4 validation.
- TCP minimum-header validation.
- TCP data-offset validation.
- Port and flag extraction.
- Payload display.

It does not establish a real TCP connection.

## 6. Malformed Packet Demonstrations

The program also submits malformed inputs.

Current examples include:

- An Ethernet frame shorter than the Ethernet header.
- A null Ethernet frame pointer.
- An IPv4 packet whose total length is smaller than its header.
- An IPv4 packet whose total length exceeds the received data.
- An IPv4 packet with an invalid header length.

These are currently smoke tests. They submit the malformed
packets and allow the packet processor to handle them, but
they do not yet contain individual automated pass/fail
assertions for every rejection case.

## 7. Sanitizer Testing

Run:

```bash
make sanitize
```

This builds the program with:

- AddressSanitizer
- UndefinedBehaviorSanitizer

These tools can help identify memory errors and certain
forms of undefined behavior during execution.

If your compiler does not support these sanitizers, use
the normal build and test commands instead.

## 8. Clean Generated Files

Run:

```bash
make clean
```

This removes the generated executable and sanitizer executable.

## 9. Interpreting Test Results

The current test summary reports the number of explicit
assertions passed and failed.

A successful assertion count does not mean that every
protocol behavior has been fully verified.

In particular, ARP, ICMP, TCP, and malformed packet
demonstrations need more dedicated assertions before
they can be considered comprehensive automated tests.

## 10. Scope of This Project

The implementation is an educational packet-processing
simulation.

It currently does not provide:

- Real network-interface communication.
- Real packet transmission.
- IPv4 fragment reassembly.
- TCP checksum verification.
- A complete TCP connection state machine.
- UDP processing.
- HTTP or web-server functionality.

Testing should therefore focus on the implemented packet
parsing, validation, checksum, and demonstration behavior.
