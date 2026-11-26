
# Custom TCP/IP Stack in C

A lightweight, educational implementation of selected Ethernet,
ARP, IPv4, ICMP, and TCP packet-processing functionality in C.

The project focuses on understanding how network packets are
structured, validated, and dispatched across protocol layers.

This is an in-memory packet-processing simulation. It does not
implement a complete operating-system network stack and does not
send or receive real network traffic through a network interface.

## Features

### Ethernet
- Parses Ethernet frame headers.
- Identifies ARP and IPv4 frames.
- Filters frames using the configured local MAC address and
  broadcast destination address.
- Uses packed structures for protocol header layouts.

### ARP
- Parses Ethernet/IPv4 ARP messages.
- Validates hardware type, protocol type, address lengths,
  opcode, and sender MAC address.
- Maintains a basic IP-to-MAC ARP cache.
- Prepares an ARP reply for requests targeting the local IP.

### IPv4
- Validates IPv4 version and header length.
- Checks that the total packet length is consistent with the
  received frame length.
- Verifies the IPv4 header checksum.
- Checks destination IP address and TTL.
- Rejects fragmented IPv4 packets. Fragment reassembly is not
  implemented.
- Dispatches supported packets to ICMP and TCP handlers.

### ICMP
- Validates ICMP packet length and checksum.
- Handles ICMP echo requests.
- Prepares an ICMP echo reply packet in memory.

### TCP
- Validates the minimum TCP header size.
- Validates the TCP data offset and header length.
- Extracts source and destination ports, flags, and payload.
- Displays a limited portion of the payload in hexadecimal form.

### Utility Functions
- Calculates Internet checksums using byte-based processing.
- Handles odd-length checksum input.
- Parses dotted-decimal IPv4 addresses with strict input validation.
- Validates basic MAC address properties.

## Project Structure

```text
TCP_IP_Stack/
├── .gitignore
├── Makefile
├── README.md
├── TESTING_GUIDE.md
├── main.c
├── tcp_ip_stack.c
└── tcp_ip_stack.h
```

| File | Responsibility |
|---|---|
| `main.c` | Demonstration packets and built-in tests |
| `tcp_ip_stack.c` | Packet parsing, validation, and protocol processing |
| `tcp_ip_stack.h` | Protocol structures, constants, and function declarations |
| `Makefile` | Build, run, test, and sanitizer commands |
| `TESTING_GUIDE.md` | Build and testing instructions |

## Requirements

- GCC or a compatible C compiler
- GNU Make
- A C99-compatible compiler

AddressSanitizer and UndefinedBehaviorSanitizer support is
required for the optional sanitizer target.

## Build

Clone the repository and enter its directory:

```bash
git clone https://github.com/abhishekjoshi13/TCP_IP_Stack.git
cd TCP_IP_Stack
```

Build the project:

```bash
make
```

Run the demonstration:

```bash
make run
```

Run the built-in tests and packet demonstrations:

```bash
make test
```

Build and run with memory and undefined-behavior sanitizers:

```bash
make sanitize
```

Remove generated binaries:

```bash
make clean
```

## Test Coverage

The current built-in test program includes:

- Valid IPv4 address parsing.
- Invalid and malformed IPv4 address rejection.
- Odd-length checksum validation.
- Null and empty checksum input handling.
- Sample ARP request processing.
- Sample ICMP echo request processing.
- Sample TCP packet processing.
- Malformed Ethernet frame submission.
- Malformed IPv4 packet submission.

The parser and checksum cases have explicit pass/fail assertions.
The packet-processing cases currently serve as demonstrations
and smoke tests; they are not all independently asserted.

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for details.

## Current Limitations

This project is an educational implementation, not a complete
or production-ready TCP/IP stack.

- It does not use raw sockets or a physical network interface.
- Prepared ARP and ICMP replies are not transmitted.
- IPv4 fragment reassembly is not implemented; fragmented packets
  are rejected.
- TCP checksum verification is not implemented.
- A complete TCP connection state machine is not implemented.
- TCP connection establishment, retransmission, congestion
  control, and teardown are not implemented.
- UDP is not implemented.
- The ARP cache does not provide comprehensive protection against
  ARP spoofing or poisoning.
- IPv4 options are not interpreted.
- Automated packet-processing assertions and continuous
  integration are not yet included.

## Possible Future Improvements

- Add TCP pseudo-header checksum verification.
- Implement IPv4 fragment reassembly.
- Add stronger ARP cache validation and protection.
- Add automated assertions for malformed and valid packets.
- Add dedicated unit tests and continuous integration.
- Implement UDP packet processing.
- Add a TCP connection state machine.
- Add an optional real network-interface backend.

## References

- RFC 791 — Internet Protocol
- RFC 792 — Internet Control Message Protocol
- RFC 793 — Transmission Control Protocol
- RFC 826 — Ethernet Address Resolution Protocol
- TCP/IP Illustrated, Volume 1 — W. Richard Stevens
