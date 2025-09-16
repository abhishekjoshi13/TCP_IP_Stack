# TCP/IP Stack Implementation

A lightweight, educational implementation of a TCP/IP network stack in C.

## Features

- Ethernet frame processing
- ARP protocol implementation  
- IP packet handling
- ICMP support (ping replies)
- Basic TCP processing

## Building

```bash
make
Running
./tcp_ip_stack
Project Structure
main.c - Main application and test simulation

tcp_ip_stack.h - Protocol definitions

tcp_ip_stack.c - Core implementation

Makefile - Build configuration
🔧 Protocol Implementation Details
Ethernet Layer (tcp_ip_stack.h)
MAC address filtering and validation

Support for ARP (0x0806) and IP (0x0800) protocol types

Frame structure parsing using packed structures

ARP Protocol (tcp_ip_stack.c)
Handles ARP requests and replies

Maintains local ARP table for IP-to-MAC mapping

Responds to ARP queries for the local IP address

IP Layer (tcp_ip_stack.c)
IPv4 packet parsing and validation

Header checksum verification using RFC-compliant algorithm

Protocol demultiplexing (ICMP, TCP)

TTL and fragmentation handling

ICMP Protocol (tcp_ip_stack.c)
Processes ICMP echo requests (ping)

Generates appropriate echo replies with correct checksums

Validates incoming ICMP packets

TCP Protocol (tcp_ip_stack.c)
Basic TCP header parsing with proper byte ordering

Port number handling and flag interpretation

Payload extraction and display

SYN flag detection for connection attempts

🧪 Testing
The implementation includes comprehensive test cases that simulate:

ARP Requests: Tests address resolution protocol handling

ICMP Echo Requests: Validates ping response capability

TCP Packets: Tests TCP header parsing and data extraction
References
RFC 791 - Internet Protocol (IP)

RFC 792 - Internet Control Message Protocol (ICMP)

RFC 793 - Transmission Control Protocol (TCP)

RFC 826 - Ethernet Address Resolution Protocol (ARP)

"TCP/IP Illustrated, Volume 1" by W. Richard Stevens

Various networking and protocol documentation
