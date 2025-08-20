"""
Data Link Layer Implementation

This layer handles frame formatting and local network delivery.
Think of it as the "postal service" for your local network - it makes sure
packets get delivered to the right computer on your immediate network.

Key concepts demonstrated:
- Ethernet frame structure
- MAC (hardware) addresses
- Error detection with checksums
- Address Resolution Protocol (ARP)
"""

import struct
import logging
from typing import Optional, Dict
from .utils import calculate_checksum

class EthernetFrame:
    """
    Ethernet Frame - The Standard Format for Local Network Communication
    
    An Ethernet frame is like an envelope that contains:
    - Destination address (where it's going)
    - Source address (where it came from) 
    - Type of contents (what's inside)
    - The actual data
    - Error detection code
    
    Frame Structure (in bytes):
    [Dest MAC: 6][Source MAC: 6][Type: 2][Data: 46-1500][Checksum: 4]
    """
    
    def __init__(self, dest_mac: str, src_mac: str, ethertype: int, payload: bytes):
        """
        Create a new Ethernet frame.
        
        Args:
            dest_mac: Destination MAC address (like "aa:bb:cc:dd:ee:ff")
            src_mac: Source MAC address
            ethertype: Type of data (0x0800 = IPv4, 0x0806 = ARP)
            payload: The actual data being sent
        """
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.ethertype = ethertype
        self.payload = payload
        self.fcs = 0  # Frame Check Sequence (calculated automatically)
    
    def to_bytes(self) -> bytes:
        """
        Convert this frame into bytes that can be sent over the network.
        
        This is like putting a letter into an envelope and writing the addresses.
        """
        # Convert MAC addresses from human-readable format to bytes
        dest_bytes = bytes.fromhex(self.dest_mac.replace(':', ''))
        src_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        
        # Build the frame header (destination, source, type)
        header = dest_bytes + src_bytes + struct.pack('!H', self.ethertype)
        
        # Add the data payload
        frame_data = header + self.payload
        
        # Calculate error detection code (like a postal code verification)
        self.fcs = calculate_checksum(frame_data)
        
        # Add the checksum to the end
        frame_data += struct.pack('!I', self.fcs)
        
        return frame_data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['EthernetFrame']:
        """
        Parse received bytes back into an Ethernet frame.
        
        This is like opening an envelope and reading the addresses and contents.
        """
        if len(data) < 18:  # Minimum valid frame size
            return None
        
        try:
            # Extract destination MAC (first 6 bytes)
            dest_mac = ':'.join(f'{b:02x}' for b in data[0:6])
            
            # Extract source MAC (next 6 bytes)
            src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
            
            # Extract frame type (next 2 bytes)
            ethertype = struct.unpack('!H', data[12:14])[0]
            
            # Extract payload (everything except last 4 bytes)
            payload = data[14:-4]
            
            # Extract checksum (last 4 bytes)
            received_fcs = struct.unpack('!I', data[-4:])[0]
            
            # Create the frame object
            frame = cls(dest_mac, src_mac, ethertype, payload)
            frame.fcs = received_fcs
            
            # Verify the frame wasn't corrupted during transmission
            frame_without_checksum = data[:-4]
            calculated_fcs = calculate_checksum(frame_without_checksum)
            
            if calculated_fcs != received_fcs:
                # Frame is corrupted - discard it
                return None
            
            return frame
            
        except Exception:
            # If we can't parse it, it's probably corrupted
            return None
    
    def __str__(self) -> str:
        """Human-readable representation of this frame."""
        return f"EthernetFrame(from={self.src_mac}, to={self.dest_mac}, type=0x{self.ethertype:04x})"

class DataLinkLayer:
    """
    Data Link Layer - Local Network Communication Manager
    
    This layer is responsible for:
    - Packaging data into frames for local delivery
    - Managing MAC addresses (hardware addresses)
    - Detecting and handling transmission errors
    - Resolving IP addresses to MAC addresses (ARP)
    
    Think of this layer as your local post office - it knows how to deliver
    mail within your neighborhood (local network).
    """
    
    def __init__(self, mac_address: str = "02:00:00:00:00:01"):
        """
        Initialize the data link layer.
        
        Args:
            mac_address: Our network card's hardware address
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.mac_address = mac_address
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"  # Special address meaning "everyone"
        
        # ARP Table - Maps IP addresses to MAC addresses
        # This is like a phone book for your local network
        self.arp_table = {
            "127.0.0.1": self.mac_address,  # Loopback address maps to ourselves
        }
        
        # Statistics for monitoring network health
        self.stats = {
            "frames_sent": 0,
            "frames_received": 0,
            "frames_dropped": 0,           # Frames we couldn't process
            "checksum_errors": 0,          # Corrupted frames detected
            "arp_requests": 0,             # Address resolution requests
            "arp_replies": 0               # Address resolution replies
        }
        
        self.logger.info(f"Data Link Layer initialized with MAC {mac_address}")
    
    def create_frame(self, payload: bytes, dest_ip: str = "127.0.0.1") -> bytes:
        """
        Package data into an Ethernet frame for transmission.
        
        This is like putting a letter into an addressed envelope.
        
        Args:
            payload: The data to send (from network layer)
            dest_ip: IP address of destination (we'll resolve to MAC)
            
        Returns:
            Complete Ethernet frame ready for transmission
        """
        try:
            # Look up the MAC address for this IP address
            dest_mac = self._resolve_mac_address(dest_ip)
            
            # Create an Ethernet frame
            # 0x0800 means "this contains IP data"
            frame = EthernetFrame(
                dest_mac=dest_mac,
                src_mac=self.mac_address,
                ethertype=0x0800,  # IPv4
                payload=payload
            )
            
            # Convert to bytes and update statistics
            frame_bytes = frame.to_bytes()
            self.stats["frames_sent"] += 1
            
            self.logger.debug(f"Created frame: {frame}")
            return frame_bytes
            
        except Exception as e:
            self.logger.error(f"Failed to create frame: {e}")
            raise
    
    def process_frame(self, frame_data: bytes) -> Optional[bytes]:
        """
        Process a received Ethernet frame.
        
        This is like opening an envelope and checking if it's addressed to us.
        
        Args:
            frame_data: Raw frame bytes from physical layer
            
        Returns:
            Payload data if frame is for us, None otherwise
        """
        frame = EthernetFrame.from_bytes(frame_data)
        
        if not frame:
            # Frame is corrupted or invalid
            self.stats["frames_dropped"] += 1
            self.stats["checksum_errors"] += 1
            self.logger.warning("Received corrupted frame")
            return None
        
        self.stats["frames_received"] += 1
        
        # Check if this frame is addressed to us
        if frame.dest_mac != self.mac_address and frame.dest_mac != self.broadcast_mac:
            # Not for us - ignore it (this is normal on shared networks)
            return None
        
        # Handle different frame types
        if frame.ethertype == 0x0800:
            # IPv4 packet - pass to network layer
            self.logger.debug(f"Received IPv4 frame from {frame.src_mac}")
            return frame.payload
            
        elif frame.ethertype == 0x0806:
            # ARP packet - handle address resolution
            self._handle_arp_packet(frame)
            return None
            
        else:
            # Unknown frame type
            self.logger.warning(f"Unknown frame type: 0x{frame.ethertype:04x}")
            return None
    
    def _resolve_mac_address(self, ip_address: str) -> str:
        """
        Find the MAC address for a given IP address.
        
        This implements a simplified version of ARP (Address Resolution Protocol).
        In a real network, this would broadcast a "who has this IP?" message.
        
        Args:
            ip_address: IP address to resolve
            
        Returns:
            MAC address for that IP
        """
        # Check our ARP table first
        if ip_address in self.arp_table:
            return self.arp_table[ip_address]
        
        # For demonstration, we'll simulate ARP resolution
        self.logger.info(f"Resolving MAC address for {ip_address}")
        
        # In a real implementation, we'd send an ARP request here
        # For now, simulate that all local IPs map to ourselves
        if ip_address.startswith("127."):
            mac = self.mac_address
        else:
            # Generate a simulated MAC address for demonstration
            import hashlib
            hash_obj = hashlib.md5(ip_address.encode())
            hash_hex = hash_obj.hexdigest()
            mac = f"02:{hash_hex[0:2]}:{hash_hex[2:4]}:{hash_hex[4:6]}:{hash_hex[6:8]}:{hash_hex[8:10]}"
        
        # Cache the result
        self.arp_table[ip_address] = mac
        self.stats["arp_requests"] += 1
        
        self.logger.debug(f"Resolved {ip_address} to MAC {mac}")
        return mac
    
    def _handle_arp_packet(self, frame: EthernetFrame):
        """
        Handle ARP (Address Resolution Protocol) packets.
        
        ARP is used to find MAC addresses for IP addresses on the local network.
        It's like asking "Hey, who has IP address 192.168.1.100?" and getting
        the response "That's me, my MAC address is aa:bb:cc:dd:ee:ff"
        """
        self.stats["arp_replies"] += 1
        self.logger.debug(f"Processed ARP packet from {frame.src_mac}")
        
        # In a full implementation, we'd parse the ARP packet here
        # and update our ARP table with the sender's information
    
    def add_arp_entry(self, ip_address: str, mac_address: str):
        """
        Manually add an entry to our ARP table.
        
        This is like adding a contact to your phone book.
        """
        self.arp_table[ip_address] = mac_address
        self.logger.info(f"Added ARP entry: {ip_address} -> {mac_address}")
    
    def get_arp_table(self) -> Dict[str, str]:
        """Get a copy of our current ARP table."""
        return self.arp_table.copy()
    
    def get_statistics(self) -> dict:
        """Get current data link layer statistics."""
        return {
            **self.stats,
            "mac_address": self.mac_address,
            "arp_table_size": len(self.arp_table)
        }
    
    def clear_arp_table(self):
        """Clear all ARP entries (except localhost)."""
        localhost_mac = self.arp_table.get("127.0.0.1", self.mac_address)
        self.arp_table.clear()
        self.arp_table["127.0.0.1"] = localhost_mac
        self.logger.info("ARP table cleared")