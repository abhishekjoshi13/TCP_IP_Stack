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
