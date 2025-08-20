"""
Utility Functions for TCP/IP Stack

This module contains helper functions used throughout the networking stack.
Think of these as the "toolkit" that all the other components use for
common tasks like calculating checksums and validating addresses.
"""

import socket
import struct
import ipaddress
import logging
from typing import Union, Optional

def calculate_checksum(data: bytes) -> int:
    """
    Calculate Internet checksum for error detection.
    
    The Internet checksum is used throughout the TCP/IP stack to detect
    transmission errors. It's like a "fingerprint" of the data that changes
    if any bits get corrupted during transmission.
    
    How it works:
    1. Split data into 16-bit chunks
    2. Add all chunks together
    3. Add any overflow back to the sum
    4. Take the one's complement (flip all bits)
    
    Args:
        data: Bytes to calculate checksum for
        
    Returns:
        16-bit checksum value
    """
    # Ensure data has even length (pad with zero if needed)
    if len(data) % 2:
        data += b'\x00'
    
    # Sum all 16-bit words
    checksum = 0
    for i in range(0, len(data), 2):
        # Unpack two bytes as a 16-bit big-endian integer
        word = struct.unpack('!H', data[i:i+2])[0]
        checksum += word
    
    # Add overflow back to the sum
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # Take one's complement (flip all bits)
    return (~checksum) & 0xFFFF

def validate_ip_address(ip_str: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    This checks both IPv4 and IPv6 formats to ensure we have a
    properly formatted IP address before trying to use it.
    
    Args:
        ip_str: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_mac_address(mac_str: str) -> bool:
    """
    Validate if a string is a valid MAC address.
    
    MAC addresses are hardware identifiers that look like:
    "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff"
    
    Args:
        mac_str: String to validate
        
    Returns:
        True if valid MAC address, False otherwise
    """
    try:
        # Remove separators and check if we have 12 hex characters
        mac_clean = mac_str.replace(':', '').replace('-', '').replace('.', '')
        
        if len(mac_clean) != 12:
            return False
        
        # Try to parse as hexadecimal
        int(mac_clean, 16)
        return True
        
    except ValueError:
        return False

def format_mac_address(mac_bytes: bytes) -> str:
    """
    Convert MAC address bytes to human-readable string.
    
    Args:
        mac_bytes: 6 bytes representing MAC address
        
    Returns:
        Formatted MAC address string like "aa:bb:cc:dd:ee:ff"
    """
    if len(mac_bytes) != 6:
        raise ValueError("MAC address must be exactly 6 bytes")
    
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def parse_mac_address(mac_str: str) -> bytes:
    """
    Convert MAC address string to bytes.
    
    Args:
        mac_str: MAC address string (with : or - separators)
        
    Returns:
        6 bytes representing the MAC address
    """
    if not validate_mac_address(mac_str):
        raise ValueError(f"Invalid MAC address: {mac_str}")
    
    # Remove separators and convert to bytes
    mac_clean = mac_str.replace(':', '').replace('-', '').replace('.', '')
    return bytes.fromhex(mac_clean)

def ip_to_int(ip_str: str) -> int:
    """
    Convert IP address string to integer.
    
    This is useful for subnet calculations and routing decisions.
    For example, "192.168.1.1" becomes 3232235777.
    
    Args:
        ip_str: IP address string
        
    Returns:
        IP address as 32-bit integer
    """
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

def int_to_ip(ip_int: int) -> str:
    """
    Convert integer back to IP address string.
    
    Args:
        ip_int: IP address as 32-bit integer
        
    Returns:
        IP address string
    """
    try:
        return str(ipaddress.IPv4Address(ip_int))
    except ValueError:
        raise ValueError(f"Invalid IP integer: {ip_int}")

def calculate_subnet_mask(prefix_length: int) -> str:
    """
    Calculate subnet mask from prefix length.
    
    For example, /24 becomes "255.255.255.0"
    This is used in routing to determine which addresses are on the same network.
    
    Args:
        prefix_length: Number of network bits (0-32)
        
    Returns:
        Subnet mask string
    """
    if not 0 <= prefix_length <= 32:
        raise ValueError("Prefix length must be between 0 and 32")
    
    # Create mask with specified number of 1s followed by 0s
    mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    return int_to_ip(mask)

def ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    """
    Check if an IP address belongs to a specific subnet.
    
    This is fundamental for routing decisions - we need to know
    which network an IP address belongs to.
    
    Args:
        ip_str: IP address to check
        subnet_str: Subnet in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        True if IP is in subnet, False otherwise
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        subnet = ipaddress.IPv4Network(subnet_str, strict=False)
        return ip in subnet
    except ValueError:
        return False

def calculate_network_address(ip_str: str, prefix_length: int) -> str:
    """
    Calculate the network address for an IP and prefix length.
    
    For example, IP "192.168.1.100" with prefix /24 gives network "192.168.1.0"
    
    Args:
        ip_str: IP address
        prefix_length: Number of network bits
        
    Returns:
        Network address string
    """
    try:
        network = ipaddress.IPv4Network(f"{ip_str}/{prefix_length}", strict=False)
        return str(network.network_address)
    except ValueError:
        raise ValueError(f"Invalid IP or prefix: {ip_str}/{prefix_length}")

def format_bytes(byte_count: int) -> str:
    """
    Format byte count in human-readable format.
    
    Converts large byte counts to KB, MB, GB for easier reading.
    
    Args:
        byte_count: Number of bytes
        
    Returns:
        Formatted string like "1.5 MB"
    """
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    elif byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.1f} MB"
    else:
        return f"{byte_count / (1024 * 1024 * 1024):.1f} GB"

def format_duration(seconds: float) -> str:
    """
    Format time duration in human-readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string like "2h 30m 15s"
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def parse_port_range(port_str: str) -> tuple:
    """
    Parse port range string into start and end ports.
    
    Handles formats like:
    - "80" -> (80, 80)
    - "8000-8080" -> (8000, 8080)
    - "1024+" -> (1024, 65535)
    
    Args:
        port_str: Port specification string
        
    Returns:
        Tuple of (start_port, end_port)
    """
    port_str = port_str.strip()
    
    if '-' in port_str:
        # Range format: "8000-8080"
        start, end = port_str.split('-', 1)
        return (int(start.strip()), int(end.strip()))
    
    elif port_str.endswith('+'):
        # Open range: "1024+"
        start = int(port_str[:-1].strip())
        return (start, 65535)
    
    else:
        # Single port: "80"
        port = int(port_str)
        return (port, port)

def is_port_in_range(port: int, port_range: tuple) -> bool:
    """
    Check if a port number falls within a given range.
    
    Args:
        port: Port number to check
        port_range: Tuple of (start_port, end_port)
        
    Returns:
        True if port is in range, False otherwise
    """
    start_port, end_port = port_range
    return start_port <= port <= end_port

def generate_random_port(start: int = 32768, end: int = 65535) -> int:
    """
    Generate a random port number in the ephemeral range.
    
    Ephemeral ports are used for outgoing connections when the
    application doesn't specify a particular port.
    
    Args:
        start: Minimum port number
        end: Maximum port number
        
    Returns:
        Random port number in range
    """
    import random
    return random.randint(start, end)

def validate_port_number(port: int) -> bool:
    """
    Validate if a number is a valid TCP/UDP port.
    
    Valid ports are 1-65535. Port 0 is reserved.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port, False otherwise
    """
    return 1 <= port <= 65535

def get_protocol_name(protocol_number: int) -> str:
    """
    Get human-readable protocol name from protocol number.
    
    These are the standard protocol numbers defined by IANA.
    
    Args:
        protocol_number: IP protocol number
        
    Returns:
        Protocol name string
    """
    protocol_map = {
        1: "ICMP",
        2: "IGMP", 
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        89: "OSPF",
        132: "SCTP"
    }
    
    return protocol_map.get(protocol_number, f"Protocol-{protocol_number}")

def create_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create a standardized logger for network components.
    
    This ensures consistent logging format across all parts
    of the TCP/IP stack for easier debugging and monitoring.
    
    Args:
        name: Logger name (usually component name)
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        # Create console handler
        handler = logging.StreamHandler()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    
    return logger

def hexdump(data: bytes, width: int = 16) -> str:
    """
    Create a hexadecimal dump of binary data for debugging.
    
    This is useful for examining packet contents and debugging
    protocol implementations.
    
    Args:
        data: Binary data to dump
        width: Number of bytes per line
        
    Returns:
        Formatted hex dump string
    """
    lines = []
    
    for i in range(0, len(data), width):
        # Extract line of data
        line_data = data[i:i+width]
        
        # Format offset
        offset = f"{i:08x}"
        
        # Format hex bytes
        hex_part = ' '.join(f"{b:02x}" for b in line_data)
        hex_part = hex_part.ljust(width * 3 - 1)  # Pad to fixed width
        
        # Format ASCII representation
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
        
        lines.append(f"{offset}  {hex_part}  |{ascii_part}|")
    
    return '\n'.join(lines)

def parse_ethernet_address(addr_str: str) -> str:
    """
    Normalize Ethernet/MAC address format.
    
    Accepts various formats and converts to standard colon-separated format.
    
    Args:
        addr_str: MAC address in various formats
        
    Returns:
        Normalized MAC address string
    """
    # Remove common separators
    addr_clean = addr_str.replace(':', '').replace('-', '').replace('.', '').replace(' ', '')
    
    # Validate length
    if len(addr_clean) != 12:
        raise ValueError(f"Invalid MAC address length: {addr_str}")
    
    # Validate hex characters
    try:
        int(addr_clean, 16)
    except ValueError:
        raise ValueError(f"Invalid MAC address format: {addr_str}")
    
    # Format with colons
    return ':'.join(addr_clean[i:i+2] for i in range(0, 12, 2)).lower()

def calculate_rtt_estimate(samples: list, alpha: float = 0.125) -> float:
    """
    Calculate estimated Round Trip Time using exponential weighted moving average.
    
    This is used in TCP for timeout calculations and congestion control.
    
    Args:
        samples: List of RTT measurements in seconds
        alpha: Smoothing factor (lower = more smoothing)
        
    Returns:
        Estimated RTT in seconds
    """
    if not samples:
        return 1.0  # Default 1 second
    
    estimate = samples[0]
    
    for sample in samples[1:]:
        estimate = (1 - alpha) * estimate + alpha * sample
    
    return estimate