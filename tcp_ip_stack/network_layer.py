"""
Network Layer Implementation

This layer handles end-to-end packet delivery across multiple networks.
Think of it as the "postal system" - it figures out how to get your mail
from your house to anywhere in the world, even through multiple post offices.

Key concepts demonstrated:
- IP packet structure and creation
- Routing decisions
- Packet fragmentation
- ICMP (error messaging)
- Time-to-Live (TTL) handling
"""

import struct
import socket
import time
import logging
from typing import Optional, List
from .utils import calculate_checksum, validate_ip_address

class IPPacket:
    """
    Internet Protocol (IP) Packet - The Universal Mail Format
    
    Every piece of data sent over the internet is packaged in an IP packet.
    Think of it as a postcard with:
    - Source address (where it came from)
    - Destination address (where it's going)
    - Instructions for postal workers (flags and options)
    - The actual message
    
    IPv4 Packet Structure:
    | Version | Header Length | Type of Service | Total Length    |
    | Identification          | Flags | Fragment Offset       |
    | Time to Live | Protocol | Header Checksum           |
    | Source IP Address                                     |
    | Destination IP Address                                |
    | Options (variable)                                    |
    | Data (payload)                                        |
    """
    
    def __init__(self, source_ip: str, dest_ip: str, protocol: int, data: bytes, 
                 ttl: int = 64, identification: int = 0):
        """
        Create a new IP packet.
        
        Args:
            source_ip: Where this packet came from
            dest_ip: Where this packet is going
            protocol: What type of data this contains (6=TCP, 17=UDP, 1=ICMP)
            data: The actual data being sent
            ttl: Time To Live - max hops before packet is discarded
            identification: Unique ID for this packet (used for fragmentation)
        """
        # Standard IPv4 header fields
        self.version = 4                    # IPv4
        self.ihl = 5                        # Internet Header Length (20 bytes)
        self.dscp = 0                       # Differentiated Services (QoS)
        self.ecn = 0                        # Explicit Congestion Notification
        self.total_length = 20 + len(data)  # Header + payload size
        self.identification = identification # Unique packet ID
        self.flags = 0b010                  # Don't Fragment flag set
        self.fragment_offset = 0            # Fragment position (for large packets)
        self.ttl = ttl                      # Hops remaining before discard
        self.protocol = protocol            # Upper layer protocol
        self.header_checksum = 0            # Error detection (calculated later)
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.options = b''                  # Optional fields
        self.data = data
    
    def to_bytes(self) -> bytes:
        """
        Convert this packet into bytes that can be transmitted.
        
        This is like writing addresses and instructions on an envelope
        in a standardized format that all postal workers understand.
        """
        # Calculate total packet size
        self.total_length = (self.ihl * 4) + len(self.data)
        
        # Pack first row of header
        version_ihl = (self.version << 4) | self.ihl
        dscp_ecn = (self.dscp << 2) | self.ecn
        flags_fragoff = (self.flags << 13) | self.fragment_offset
        
        # Build header without checksum first
        header = struct.pack('!BBHHHBBH',
                           version_ihl,           # Version + Header Length
                           dscp_ecn,              # Service Type
                           self.total_length,     # Total packet length
                           self.identification,   # Packet ID
                           flags_fragoff,         # Flags + Fragment Offset
                           self.ttl,              # Time To Live
                           self.protocol,         # Protocol (TCP/UDP/ICMP)
                           0)                     # Checksum placeholder
        
        # Add IP addresses (convert from dotted notation to 4-byte format)
        header += socket.inet_aton(self.source_ip)
        header += socket.inet_aton(self.dest_ip)
        
        # Add any optional fields
        header += self.options
        
        # Calculate header checksum for error detection
        self.header_checksum = calculate_checksum(header)
        
        # Rebuild header with correct checksum
        header = struct.pack('!BBHHHBBH',
                           version_ihl,
                           dscp_ecn,
                           self.total_length,
                           self.identification,
                           flags_fragoff,
                           self.ttl,
                           self.protocol,
                           self.header_checksum)
        
        header += socket.inet_aton(self.source_ip)
        header += socket.inet_aton(self.dest_ip)
        header += self.options
        
        # Combine header and data
        return header + self.data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['IPPacket']:
        """
        Parse bytes back into an IP packet.
        
        This is like a postal worker reading the addresses and instructions
        from a received envelope.
        """
        if len(data) < 20:  # Minimum IP header size
            return None
        
        try:
            # Parse the fixed header fields
            header_data = struct.unpack('!BBHHHBBH', data[:12])
            version_ihl, dscp_ecn, total_length, identification, flags_fragoff, \
            ttl, protocol, header_checksum = header_data
            
            # Extract individual fields
            version = (version_ihl >> 4) & 0xF
            ihl = version_ihl & 0xF
            
            # Verify this is IPv4
            if version != 4:
                return None
            
            # Calculate header length and verify packet size
            header_length = ihl * 4
            if len(data) < header_length:
                return None
            
            # Extract IP addresses
            source_ip = socket.inet_ntoa(data[12:16])
            dest_ip = socket.inet_ntoa(data[16:20])
            
            # Extract options and payload
            options = data[20:header_length]
            payload = data[header_length:total_length]
            
            # Create packet object
            packet = cls(source_ip, dest_ip, protocol, payload, ttl, identification)
            
            # Copy additional fields
            packet.dscp = (dscp_ecn >> 2) & 0x3F
            packet.ecn = dscp_ecn & 0x3
            packet.flags = (flags_fragoff >> 13) & 0x7
            packet.fragment_offset = flags_fragoff & 0x1FFF
            packet.header_checksum = header_checksum
            packet.options = options
            
            return packet
            
        except Exception:
            return None
    
    def __str__(self) -> str:
        """Human-readable representation of this packet."""
        return f"IPPacket({self.source_ip} -> {self.dest_ip}, proto={self.protocol}, {len(self.data)} bytes)"

class NetworkLayer:
    """
    Network Layer - Internet Routing and Delivery Service
    
    This layer is responsible for:
    - Creating and parsing IP packets
    - Making routing decisions (which way should packets go?)
    - Handling packet fragmentation (breaking large packets into pieces)
    - Managing Time-to-Live to prevent infinite loops
    - Generating ICMP error messages
    
    Think of this as the postal service that figures out how to get
    your mail from your local post office to anywhere in the world.
    """
    
    def __init__(self, local_ip: str = "127.0.0.1"):
        """
        Initialize the network layer.
        
        Args:
            local_ip: Our IP address on the network
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.local_ip = local_ip
        self._packet_id_counter = 1  # For generating unique packet IDs
        
        # Network statistics for monitoring
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "packets_forwarded": 0,
            "packets_dropped": 0,
            "icmp_sent": 0,
            "fragments_created": 0,
            "fragments_reassembled": 0
        }
        
        # Fragment reassembly buffer (for handling large packets)
        self.fragment_buffer = {}
        
        self.logger.info(f"Network layer initialized with IP {local_ip}")
    
    def create_packet(self, data: bytes, destination_ip: str, protocol: int, 
                     ttl: int = 64) -> IPPacket:
        """
        Create a new IP packet for transmission.
        
        This is like addressing an envelope and preparing it for mailing.
        
        Args:
            data: The data to send
            destination_ip: Where to send it
            protocol: What type of data (TCP=6, UDP=17, ICMP=1)
            ttl: Maximum hops before packet is discarded
            
        Returns:
            Ready-to-send IP packet
        """
        # Validate the destination IP address
        if not validate_ip_address(destination_ip):
            raise ValueError(f"Invalid destination IP: {destination_ip}")
        
        # Generate unique packet ID
        packet_id = self._get_next_packet_id()
        
        # Create the packet
        packet = IPPacket(
            source_ip=self.local_ip,
            dest_ip=destination_ip,
            protocol=protocol,
            data=data,
            ttl=ttl,
            identification=packet_id
        )
        
        self.stats["packets_sent"] += 1
        self.logger.debug(f"Created packet: {packet}")
        
        return packet
    
    def process_packet(self, packet_data: bytes) -> Optional[tuple]:
        """
        Process a received IP packet.
        
        This is like a postal worker examining a received package and
        deciding what to do with it (deliver, forward, or return to sender).
        
        Args:
            packet_data: Raw packet bytes
            
        Returns:
            Tuple of (payload_data, source_ip, protocol) if packet is for us,
            None otherwise
        """
        packet = IPPacket.from_bytes(packet_data)
        
        if not packet:
            self.stats["packets_dropped"] += 1
            self.logger.warning("Received malformed IP packet")
            return None
        
        self.stats["packets_received"] += 1
        
        # Check if packet is addressed to us
        if packet.dest_ip != self.local_ip and packet.dest_ip != "255.255.255.255":
            # Not for us - in a router, we'd forward it
            self.logger.debug(f"Packet not for us (dest: {packet.dest_ip})")
            return None
        
        # Check Time-to-Live
        if packet.ttl <= 0:
            self.logger.warning("Packet TTL expired - dropping")
            self._send_icmp_time_exceeded(packet.source_ip)
            self.stats["packets_dropped"] += 1
            return None
        
        # Handle fragmented packets
        if packet.fragment_offset > 0 or (packet.flags & 0x1):  # More Fragments flag
            return self._handle_fragmented_packet(packet)
        
        # Packet is for us and ready to process
        self.logger.debug(f"Processing packet: {packet}")
        return (packet.data, packet.source_ip, packet.protocol)
    
    def fragment_packet(self, packet: IPPacket, mtu: int = 1500) -> List[IPPacket]:
        """
        Break a large packet into smaller fragments.
        
        This is like breaking a large package into smaller boxes that
        can fit through the mail system, each with instructions on
        how to reassemble them at the destination.
        
        Args:
            packet: Large packet to fragment
            mtu: Maximum Transmission Unit (largest packet size allowed)
            
        Returns:
            List of smaller packet fragments
        """
        # Calculate maximum payload size per fragment
        max_payload = mtu - 20  # IP header is 20 bytes
        max_payload = (max_payload // 8) * 8  # Must be multiple of 8
        
        if len(packet.data) <= max_payload:
            # No fragmentation needed
            return [packet]
        
        fragments = []
        data = packet.data
        offset = 0
        
        while offset < len(data):
            # Calculate fragment size
            fragment_size = min(max_payload, len(data) - offset)
            fragment_data = data[offset:offset + fragment_size]
            
            # Create fragment packet
            fragment = IPPacket(
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                protocol=packet.protocol,
                data=fragment_data,
                ttl=packet.ttl,
                identification=packet.identification
            )
            
            # Set fragment offset (in 8-byte units)
            fragment.fragment_offset = offset // 8
            
            # Set More Fragments flag for all except last fragment
            if offset + fragment_size < len(data):
                fragment.flags = 0x1  # More Fragments
            else:
                fragment.flags = 0x0  # Last Fragment
            
            fragments.append(fragment)
            offset += fragment_size
        
        self.stats["fragments_created"] += len(fragments)
        self.logger.info(f"Fragmented packet into {len(fragments)} pieces")
        
        return fragments
    
    def _handle_fragmented_packet(self, packet: IPPacket) -> Optional[tuple]:
        """
        Handle reassembly of fragmented packets.
        
        This is like collecting all the pieces of a package that was
        broken into multiple shipments and putting them back together.
        """
        fragment_key = (packet.source_ip, packet.identification)
        
        # Initialize fragment buffer for this packet if needed
        if fragment_key not in self.fragment_buffer:
            self.fragment_buffer[fragment_key] = {
                'fragments': {},
                'last_received': time.time(),
                'total_length': None
            }
        
        # Store this fragment
        self.fragment_buffer[fragment_key]['fragments'][packet.fragment_offset] = packet
        self.fragment_buffer[fragment_key]['last_received'] = time.time()
        
        # Check if this is the last fragment
        if packet.flags & 0x1 == 0:  # More Fragments flag is clear
            # This is the last fragment - we now know total length
            last_offset = packet.fragment_offset * 8
            self.fragment_buffer[fragment_key]['total_length'] = last_offset + len(packet.data)
        
        # Try to reassemble if we have all fragments
        return self._try_reassemble_packet(fragment_key)
    
    def _try_reassemble_packet(self, fragment_key: tuple) -> Optional[tuple]:
        """
        Attempt to reassemble a complete packet from fragments.
        """
        fragment_info = self.fragment_buffer[fragment_key]
        fragments = fragment_info['fragments']
        total_length = fragment_info['total_length']
        
        if total_length is None:
            # Don't know total length yet - last fragment not received
            return None
        
        # Check if we have all fragments
        current_length = 0
        sorted_offsets = sorted(fragments.keys())
        
        for i, offset in enumerate(sorted_offsets):
            expected_offset = current_length // 8
            if offset != expected_offset:
                # Missing fragment
                return None
            current_length += len(fragments[offset].data)
        
        if current_length != total_length:
            # Still missing fragments
            return None
        
        # We have all fragments - reassemble
        reassembled_data = b''
        for offset in sorted_offsets:
            reassembled_data += fragments[offset].data
        
        # Clean up fragment buffer
        first_fragment = fragments[sorted_offsets[0]]
        del self.fragment_buffer[fragment_key]
        
        self.stats["fragments_reassembled"] += 1
        self.logger.info(f"Successfully reassembled packet from {len(fragments)} fragments")
        
        return (reassembled_data, first_fragment.source_ip, first_fragment.protocol)
    
    def _send_icmp_time_exceeded(self, dest_ip: str):
        """
        Send an ICMP "Time Exceeded" error message.
        
        This is like the postal service sending you a notice that
        your mail couldn't be delivered because it went through
        too many post offices.
        """
        # Create ICMP Time Exceeded message
        icmp_data = struct.pack('!BBHI', 11, 0, 0, 0)  # Type 11, Code 0
        
        # Create IP packet for ICMP message
        icmp_packet = self.create_packet(icmp_data, dest_ip, 1)  # Protocol 1 = ICMP
        
        self.stats["icmp_sent"] += 1
        self.logger.debug(f"Sent ICMP Time Exceeded to {dest_ip}")
        
        return icmp_packet
    
    def ping(self, destination_ip: str, timeout: float = 1.0) -> dict:
        """
        Send an ICMP ping to test connectivity.
        
        This is like sending a "test message" to see if someone
        is reachable and how long it takes to get a response.
        
        Args:
            destination_ip: Target to ping
            timeout: How long to wait for response
            
        Returns:
            Dictionary with ping results
        """
        start_time = time.time()
        
        # Create ICMP Echo Request
        icmp_id = self._get_next_packet_id() & 0xFFFF
        icmp_seq = 1
        icmp_data = struct.pack('!BBHHH', 8, 0, 0, icmp_id, icmp_seq)  # Type 8 = Echo Request
        
        # Calculate ICMP checksum
        icmp_checksum = calculate_checksum(icmp_data)
        icmp_data = struct.pack('!BBHHH', 8, 0, icmp_checksum, icmp_id, icmp_seq)
        
        # Create IP packet
        packet = self.create_packet(icmp_data, destination_ip, 1)  # Protocol 1 = ICMP
        
        # For demonstration, simulate ping response
        elapsed_time = time.time() - start_time
        
        self.logger.info(f"PING {destination_ip}: time={elapsed_time*1000:.1f}ms")
        
        return {
            "destination": destination_ip,
            "bytes": len(icmp_data),
            "time_ms": elapsed_time * 1000,
            "ttl": 64,
            "success": True
        }
    
    def _get_next_packet_id(self) -> int:
        """Generate a unique packet ID."""
        packet_id = self._packet_id_counter
        self._packet_id_counter = (self._packet_id_counter + 1) % 65536
        return packet_id
    
    def get_statistics(self) -> dict:
        """Get current network layer statistics."""
        return {
            **self.stats,
            "local_ip": self.local_ip,
            "fragment_buffers": len(self.fragment_buffer)
        }
    
    def cleanup_old_fragments(self, max_age: float = 30.0):
        """
        Clean up old fragment buffers to prevent memory leaks.
        
        In real networks, fragments that don't get reassembled within
        a reasonable time are discarded.
        """
        current_time = time.time()
        expired_keys = []
        
        for key, fragment_info in self.fragment_buffer.items():
            if current_time - fragment_info['last_received'] > max_age:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.fragment_buffer[key]
            self.logger.debug(f"Cleaned up expired fragment buffer for {key}")