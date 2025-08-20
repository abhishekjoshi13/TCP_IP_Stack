"""
Transport Layer Implementation

This layer provides reliable communication between applications.
Think of it as the "guaranteed delivery service" - it ensures your data
gets delivered in the right order, without errors, and handles problems gracefully.

Key concepts demonstrated:
- TCP reliable connection-oriented communication
- UDP fast connectionless communication  
- Port numbers (application addressing)
- Flow control and congestion management
- Connection state management
"""

import struct
import socket
import threading
import time
import logging
from typing import Dict, Optional, Tuple, Any
from enum import Enum
from .utils import calculate_checksum

class TCPState(Enum):
    """
    TCP Connection States - The Life Cycle of a Connection
    
    These states represent the different phases of a TCP connection,
    like the stages of a phone call (dialing, ringing, talking, hanging up).
    """
    CLOSED = "CLOSED"               # No connection
    LISTEN = "LISTEN"               # Waiting for incoming connections
    SYN_SENT = "SYN_SENT"          # Attempting to connect
    SYN_RECEIVED = "SYN_RECEIVED"   # Connection request received
    ESTABLISHED = "ESTABLISHED"     # Active connection
    FIN_WAIT_1 = "FIN_WAIT_1"      # Starting to close connection
    FIN_WAIT_2 = "FIN_WAIT_2"      # Waiting for final close
    CLOSE_WAIT = "CLOSE_WAIT"       # Waiting to close our side
    CLOSING = "CLOSING"             # Both sides closing simultaneously
    LAST_ACK = "LAST_ACK"          # Waiting for final acknowledgment
    TIME_WAIT = "TIME_WAIT"         # Ensuring connection is fully closed

class TCPPacket:
    """
    Transmission Control Protocol (TCP) Packet - Reliable Communication
    
    TCP is like registered mail - it guarantees delivery, maintains order,
    and provides receipts (acknowledgments) for everything sent.
    
    TCP Header Structure:
    | Source Port | Destination Port |
    | Sequence Number              |
    | Acknowledgment Number        |
    | Header Len | Flags | Window Size |
    | Checksum   | Urgent Pointer     |
    | Options (variable)            |
    | Data                         |
    """
    
    def __init__(self, source_port: int, dest_port: int, seq_num: int = 0, 
                 ack_num: int = 0, flags: int = 0, window_size: int = 65535, data: bytes = b''):
        """
        Create a TCP packet.
        
        Args:
            source_port: Which application is sending (like a return address)
            dest_port: Which application should receive (like addressing an apartment number)
            seq_num: Position of this data in the stream
            ack_num: Last sequence number we successfully received
            flags: Control bits (SYN=connect, ACK=acknowledge, FIN=finish, etc.)
            window_size: How much data we can receive right now
            data: The actual application data
        """
        self.source_port = source_port
        self.dest_port = dest_port
        self.sequence_number = seq_num
        self.acknowledgment_number = ack_num
        self.header_length = 5  # 20 bytes (minimum)
        self.flags = flags
        self.window_size = window_size
        self.checksum = 0
        self.urgent_pointer = 0
        self.options = b''
        self.data = data
        
        # Flag bit definitions for easy access
        self.flag_fin = bool(flags & 0x01)  # Finish connection
        self.flag_syn = bool(flags & 0x02)  # Synchronize sequence numbers
        self.flag_rst = bool(flags & 0x04)  # Reset connection
        self.flag_psh = bool(flags & 0x08)  # Push data immediately
        self.flag_ack = bool(flags & 0x10)  # Acknowledgment field valid
        self.flag_urg = bool(flags & 0x20)  # Urgent pointer valid
    
    def to_bytes(self, source_ip: str = "127.0.0.1", dest_ip: str = "127.0.0.1") -> bytes:
        """
        Convert TCP packet to bytes for transmission.
        
        This includes calculating the checksum to detect any errors
        that might occur during transmission.
        """
        # Build TCP header
        header = struct.pack('!HHLLBBHHH',
                           self.source_port,         # Source port
                           self.dest_port,           # Destination port
                           self.sequence_number,     # Sequence number
                           self.acknowledgment_number, # Ack number
                           (self.header_length << 4), # Header length in upper 4 bits
                           self.flags,               # Control flags
                           self.window_size,         # Window size
                           0,                        # Checksum (calculated below)
                           self.urgent_pointer)      # Urgent pointer
        
        # Add options and data
        packet_data = header + self.options + self.data
        
        # Calculate TCP checksum using pseudo-header
        pseudo_header = socket.inet_aton(source_ip) + socket.inet_aton(dest_ip) + \
                       struct.pack('!BBH', 0, 6, len(packet_data))  # Protocol 6 = TCP
        
        checksum_data = pseudo_header + packet_data
        self.checksum = calculate_checksum(checksum_data)
        
        # Rebuild header with correct checksum
        header = struct.pack('!HHLLBBHHH',
                           self.source_port,
                           self.dest_port,
                           self.sequence_number,
                           self.acknowledgment_number,
                           (self.header_length << 4),
                           self.flags,
                           self.window_size,
                           self.checksum,
                           self.urgent_pointer)
        
        return header + self.options + self.data
    
    def __str__(self) -> str:
        """Human-readable representation of this TCP packet."""
        flag_str = ""
        if self.flag_syn: flag_str += "SYN "
        if self.flag_ack: flag_str += "ACK "
        if self.flag_fin: flag_str += "FIN "
        if self.flag_rst: flag_str += "RST "
        
        return f"TCP({self.source_port}->{self.dest_port} {flag_str}seq={self.sequence_number} ack={self.acknowledgment_number})"

class UDPPacket:
    """
    User Datagram Protocol (UDP) Packet - Fast Communication
    
    UDP is like sending a postcard - it's fast and simple, but there's
    no guarantee it will arrive or arrive in order. Good for real-time
    applications like video calls where speed matters more than perfection.
    
    UDP Header Structure (much simpler than TCP):
    | Source Port | Destination Port |
    | Length      | Checksum         |
    | Data                          |
    """
    
    def __init__(self, source_port: int, dest_port: int, data: bytes = b''):
        """
        Create a UDP packet.
        
        Args:
            source_port: Sending application
            dest_port: Receiving application  
            data: Application data to send
        """
        self.source_port = source_port
        self.dest_port = dest_port
        self.length = 8 + len(data)  # Header is always 8 bytes
        self.checksum = 0
        self.data = data
    
    def to_bytes(self, source_ip: str = "127.0.0.1", dest_ip: str = "127.0.0.1") -> bytes:
        """Convert UDP packet to bytes for transmission."""
        # Build UDP header
        header = struct.pack('!HHHH',
                           self.source_port,    # Source port
                           self.dest_port,      # Destination port
                           self.length,         # Total length
                           0)                   # Checksum placeholder
        
        packet_data = header + self.data
        
        # Calculate UDP checksum using pseudo-header
        pseudo_header = socket.inet_aton(source_ip) + socket.inet_aton(dest_ip) + \
                       struct.pack('!BBH', 0, 17, self.length)  # Protocol 17 = UDP
        
        checksum_data = pseudo_header + packet_data
        self.checksum = calculate_checksum(checksum_data)
        
        # Rebuild header with correct checksum
        header = struct.pack('!HHHH',
                           self.source_port,
                           self.dest_port,
                           self.length,
                           self.checksum)
        
        return header + self.data
    
    def __str__(self) -> str:
        """Human-readable representation of this UDP packet."""
        return f"UDP({self.source_port}->{self.dest_port} {len(self.data)} bytes)"

class TCPConnection:
    """
    TCP Connection State Management
    
    This class manages the state of a single TCP connection, handling
    the complex process of establishing connections, transferring data
    reliably, and closing connections gracefully.
    """
    
    def __init__(self, local_port: int, remote_ip: str, remote_port: int):
        """
        Initialize a TCP connection.
        
        Args:
            local_port: Our port number
            remote_ip: Other party's IP address
            remote_port: Other party's port number
        """
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        
        # Connection state
        self.state = TCPState.CLOSED
        self.local_seq = 1000  # Our sequence number
        self.remote_seq = 0    # Their sequence number
        self.last_ack = 0      # Last acknowledgment sent
        
        # Flow control
        self.send_window = 65535    # How much we can send
        self.receive_window = 65535  # How much we can receive
        
        # Buffers
        self.send_buffer = b''      # Data waiting to be sent
        self.receive_buffer = b''   # Data waiting to be delivered
        
        # Timing and retransmission
        self.last_activity = time.time()
        self.retransmit_timeout = 1.0
        
        self.logger = logging.getLogger(f"TCP-{local_port}-{remote_ip}:{remote_port}")
    
    def connect(self) -> bool:
        """
        Initiate TCP connection (client side).
        
        This implements the famous "three-way handshake":
        1. Client sends SYN (synchronize)
        2. Server responds with SYN-ACK
        3. Client responds with ACK
        
        Like a polite conversation:
        "Hello, can we talk?" "Yes, hello to you too!" "Great, let's start!"
        """
        if self.state != TCPState.CLOSED:
            return False
        
        # Send SYN packet
        syn_packet = TCPPacket(
            source_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.local_seq,
            flags=0x02  # SYN flag
        )
        
        self.state = TCPState.SYN_SENT
        self.local_seq += 1  # SYN consumes one sequence number
        self.last_activity = time.time()
        
        self.logger.info(f"Initiating connection: {syn_packet}")
        return True
    
    def accept_connection(self, syn_packet: TCPPacket) -> TCPPacket:
        """
        Accept incoming connection (server side).
        
        Responds to the client's SYN with our own SYN-ACK.
        """
        if self.state != TCPState.LISTEN:
            return None
        
        # Store client's sequence number
        self.remote_seq = syn_packet.sequence_number + 1
        
        # Send SYN-ACK response
        synack_packet = TCPPacket(
            source_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.local_seq,
            ack_num=self.remote_seq,
            flags=0x12  # SYN + ACK flags
        )
        
        self.state = TCPState.SYN_RECEIVED
        self.local_seq += 1  # SYN consumes one sequence number
        self.last_activity = time.time()
        
        self.logger.info(f"Accepting connection: {synack_packet}")
        return synack_packet
    
    def send_data(self, data: bytes) -> TCPPacket:
        """
        Send application data over the connection.
        
        TCP breaks large data into segments and ensures reliable delivery.
        """
        if self.state != TCPState.ESTABLISHED:
            raise Exception(f"Cannot send data in state {self.state}")
        
        # Create data packet
        data_packet = TCPPacket(
            source_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.local_seq,
            ack_num=self.remote_seq,
            flags=0x18,  # PSH + ACK flags (push data, acknowledge)
            data=data
        )
        
        self.local_seq += len(data)  # Data consumes sequence numbers
        self.last_activity = time.time()
        
        self.logger.debug(f"Sending {len(data)} bytes: {data_packet}")
        return data_packet
    
    def close_connection(self) -> TCPPacket:
        """
        Initiate connection close.
        
        TCP uses a "four-way handshake" to close connections gracefully:
        1. One side sends FIN (finished)
        2. Other side sends ACK (acknowledged)
        3. Other side sends FIN (finished too)
        4. First side sends ACK (acknowledged)
        """
        if self.state not in [TCPState.ESTABLISHED, TCPState.CLOSE_WAIT]:
            return None
        
        # Send FIN packet
        fin_packet = TCPPacket(
            source_port=self.local_port,
            dest_port=self.remote_port,
            seq_num=self.local_seq,
            ack_num=self.remote_seq,
            flags=0x11  # FIN + ACK flags
        )
        
        if self.state == TCPState.ESTABLISHED:
            self.state = TCPState.FIN_WAIT_1
        elif self.state == TCPState.CLOSE_WAIT:
            self.state = TCPState.LAST_ACK
        
        self.local_seq += 1  # FIN consumes one sequence number
        self.last_activity = time.time()
        
        self.logger.info(f"Closing connection: {fin_packet}")
        return fin_packet

class TransportLayer:
    """
    Transport Layer - Application Communication Manager
    
    This layer provides:
    - Port-based application addressing (like apartment numbers)
    - Reliable data delivery (TCP) or fast delivery (UDP)
    - Flow control (don't overwhelm the receiver)
    - Error recovery (retransmit lost packets)
    - Connection management (setup, maintain, teardown)
    
    Think of this layer as a postal service that can provide either:
    - Registered mail with delivery confirmation (TCP)
    - Regular mail that's fast but not guaranteed (UDP)
    """
    
    def __init__(self):
        """Initialize the transport layer."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Port management
        self.next_ephemeral_port = 32768  # Starting point for automatic port assignment
        self.port_bindings = {}  # Which applications are using which ports
        
        # Connection tracking
        self.tcp_connections: Dict[Tuple[int, str, int], TCPConnection] = {}
        self.udp_sockets = {}
        
        # Statistics for monitoring
        self.stats = {
            "tcp_connections_opened": 0,
            "tcp_connections_closed": 0,
            "tcp_bytes_sent": 0,
            "tcp_bytes_received": 0,
            "udp_packets_sent": 0,
            "udp_packets_received": 0,
            "udp_bytes_sent": 0,
            "udp_bytes_received": 0,
            "port_allocation_errors": 0
        }
        
        self.logger.info("Transport layer initialized")
    
    def allocate_port(self, requested_port: Optional[int] = None) -> int:
        """
        Allocate a port for an application.
        
        Ports are like apartment numbers - each application needs a unique
        number so the network knows where to deliver data.
        
        Args:
            requested_port: Specific port wanted, or None for automatic assignment
            
        Returns:
            Allocated port number
        """
        if requested_port:
            # Check if specific port is available
            if requested_port in self.port_bindings:
                self.stats["port_allocation_errors"] += 1
                raise Exception(f"Port {requested_port} already in use")
            
            self.port_bindings[requested_port] = True
            self.logger.debug(f"Allocated requested port {requested_port}")
            return requested_port
        
        else:
            # Find available ephemeral port
            while self.next_ephemeral_port in self.port_bindings:
                self.next_ephemeral_port += 1
                if self.next_ephemeral_port > 65535:
                    self.next_ephemeral_port = 32768  # Wrap around
            
            port = self.next_ephemeral_port
            self.port_bindings[port] = True
            self.next_ephemeral_port += 1
            
            self.logger.debug(f"Allocated ephemeral port {port}")
            return port
    
    def release_port(self, port: int):
        """Release a port so other applications can use it."""
        if port in self.port_bindings:
            del self.port_bindings[port]
            self.logger.debug(f"Released port {port}")
    
    def create_tcp_connection(self, remote_ip: str, remote_port: int, 
                             local_port: Optional[int] = None) -> TCPConnection:
        """
        Create a new TCP connection.
        
        TCP connections are like phone calls - you establish a connection,
        have a conversation, then hang up.
        
        Args:
            remote_ip: IP address to connect to
            remote_port: Port number to connect to
            local_port: Our port (allocated automatically if not specified)
            
        Returns:
            New TCP connection object
        """
        if not local_port:
            local_port = self.allocate_port()
        
        connection_key = (local_port, remote_ip, remote_port)
        
        if connection_key in self.tcp_connections:
            raise Exception(f"Connection already exists: {connection_key}")
        
        connection = TCPConnection(local_port, remote_ip, remote_port)
        self.tcp_connections[connection_key] = connection
        
        self.stats["tcp_connections_opened"] += 1
        self.logger.info(f"Created TCP connection: {local_port} -> {remote_ip}:{remote_port}")
        
        return connection
    
    def send_tcp_data(self, connection: TCPConnection, data: bytes) -> TCPPacket:
        """
        Send data reliably using TCP.
        
        TCP guarantees that data arrives in order and without errors.
        """
        packet = connection.send_data(data)
        self.stats["tcp_bytes_sent"] += len(data)
        return packet
    
    def send_udp_data(self, source_port: int, dest_ip: str, dest_port: int, 
                     data: bytes) -> UDPPacket:
        """
        Send data quickly using UDP.
        
        UDP is fast but doesn't guarantee delivery - like shouting across a room.
        Good for real-time applications where speed matters more than perfection.
        
        Args:
            source_port: Our port number
            dest_ip: Where to send the data
            dest_port: Which application to send to
            data: The data to send
            
        Returns:
            UDP packet ready for transmission
        """
        packet = UDPPacket(source_port, dest_port, data)
        self.stats["udp_packets_sent"] += 1
        self.stats["udp_bytes_sent"] += len(data)
        
        self.logger.debug(f"Sending UDP data: {packet}")
        return packet
    
    def process_tcp_packet(self, packet_data: bytes, source_ip: str) -> Optional[bytes]:
        """
        Process a received TCP packet.
        
        This handles the complex TCP state machine - managing connections,
        acknowledging data, handling retransmissions, etc.
        """
        # Parse TCP header (simplified parsing for demonstration)
        if len(packet_data) < 20:
            return None
        
        header = struct.unpack('!HHLLBBHHH', packet_data[:20])
        source_port, dest_port, seq_num, ack_num, header_len_flags, \
        flags, window_size, checksum, urgent_ptr = header
        
        # Extract header length and flags
        header_length = (header_len_flags >> 4) * 4
        payload = packet_data[header_length:]
        
        # Find the connection this packet belongs to
        connection_key = (dest_port, source_ip, source_port)
        connection = self.tcp_connections.get(connection_key)
        
        if not connection:
            self.logger.warning(f"Received TCP packet for unknown connection: {connection_key}")
            return None
        
        # Update connection state based on packet
        if flags & 0x02:  # SYN flag
            self.logger.info(f"Received SYN from {source_ip}:{source_port}")
        
        if flags & 0x10:  # ACK flag
            connection.last_ack = ack_num
        
        if flags & 0x01:  # FIN flag
            self.logger.info(f"Received FIN from {source_ip}:{source_port}")
            if connection.state == TCPState.ESTABLISHED:
                connection.state = TCPState.CLOSE_WAIT
        
        # If there's data, deliver it to the application
        if payload:
            self.stats["tcp_bytes_received"] += len(payload)
            connection.receive_buffer += payload
            return payload
        
        return None
    
    def process_udp_packet(self, packet_data: bytes, source_ip: str) -> Optional[Tuple[bytes, int, int]]:
        """
        Process a received UDP packet.
        
        UDP processing is much simpler than TCP - just extract the data
        and deliver it to the application.
        
        Returns:
            Tuple of (data, source_port, dest_port) if valid, None otherwise
        """
        if len(packet_data) < 8:  # Minimum UDP header size
            return None
        
        # Parse UDP header
        header = struct.unpack('!HHHH', packet_data[:8])
        source_port, dest_port, length, checksum = header
        
        # Extract payload
        payload = packet_data[8:length]
        
        self.stats["udp_packets_received"] += 1
        self.stats["udp_bytes_received"] += len(payload)
        
        self.logger.debug(f"Received UDP packet: {source_ip}:{source_port} -> {dest_port}")
        return (payload, source_port, dest_port)
    
    def close_tcp_connection(self, connection: TCPConnection) -> TCPPacket:
        """
        Close a TCP connection gracefully.
        
        This initiates the four-way handshake to cleanly terminate the connection.
        """
        fin_packet = connection.close_connection()
        
        if fin_packet:
            self.stats["tcp_connections_closed"] += 1
            self.logger.info(f"Closing TCP connection: {connection.local_port} -> {connection.remote_ip}:{connection.remote_port}")
        
        return fin_packet
    
    def get_statistics(self) -> dict:
        """Get current transport layer statistics."""
        return {
            **self.stats,
            "active_tcp_connections": len(self.tcp_connections),
            "allocated_ports": len(self.port_bindings),
            "available_ports": 65535 - len(self.port_bindings)
        }
    
    def cleanup_closed_connections(self):
        """
        Remove connections that have been properly closed.
        
        This prevents memory leaks by cleaning up old connection state.
        """
        closed_connections = []
        
        for key, connection in self.tcp_connections.items():
            if connection.state == TCPState.CLOSED:
                closed_connections.append(key)
                self.release_port(connection.local_port)
        
        for key in closed_connections:
            del self.tcp_connections[key]
            self.logger.debug(f"Cleaned up closed connection: {key}")
    
    def get_tcp_connections(self) -> Dict[str, Any]:
        """Get information about active TCP connections."""
        connections = {}
        
        for key, connection in self.tcp_connections.items():
            local_port, remote_ip, remote_port = key
            connections[f"{local_port}->{remote_ip}:{remote_port}"] = {
                "state": connection.state.value,
                "local_seq": connection.local_seq,
                "remote_seq": connection.remote_seq,
                "send_window": connection.send_window,
                "receive_window": connection.receive_window,
                "last_activity": connection.last_activity
            }
        
        return connections