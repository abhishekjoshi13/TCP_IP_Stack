#!/usr/bin/env python3
"""
Packet Sniffer Example

This example demonstrates network packet capture and analysis using
our TCP/IP stack implementation. It shows how to monitor network traffic
and understand what's happening at different protocol layers.

Think of this as a "network detective tool" that lets you see and
analyze all the communication happening on your network.
"""

import sys
import time
import threading
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Add the parent directory to the path so we can import our TCP/IP stack
sys.path.insert(0, str(Path(__file__).parent.parent))

from tcp_ip_stack import TCPIPStack, create_logger, EthernetFrame, IPPacket

class PacketSniffer:
    """
    Network Packet Capture and Analysis Tool
    
    This class demonstrates how to:
    - Capture network packets in real-time
    - Parse and analyze different protocol layers
    - Filter packets based on various criteria
    - Display packet information in human-readable format
    - Save capture data for later analysis
    """
    
    def __init__(self, stack: TCPIPStack):
        """
        Initialize the packet sniffer.
        
        Args:
            stack: TCP/IP stack instance for packet capture
        """
        self.stack = stack
        self.logger = create_logger("PacketSniffer")
        self.running = False
        self.capture_thread: Optional[threading.Thread] = None
        
        # Capture statistics and data
        self.captured_packets: List[Dict] = []
        self.stats = {
            "total_packets": 0,
            "ethernet_frames": 0,
            "ip_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "capture_start": None,
            "capture_duration": 0
        }
        
        # Filtering options
        self.filters = {
            "protocol": None,      # Filter by protocol (TCP, UDP, ICMP, etc.)
            "source_ip": None,     # Filter by source IP
            "dest_ip": None,       # Filter by destination IP
            "port": None,          # Filter by port number
            "min_size": 0,         # Minimum packet size
            "max_size": 65535      # Maximum packet size
        }
        
        # Display options
        self.display_options = {
            "show_ethernet": True,    # Show Ethernet frame details
            "show_ip": True,          # Show IP packet details
            "show_transport": True,   # Show TCP/UDP details
            "show_data": False,       # Show packet data (can be verbose)
            "max_data_bytes": 64,     # Max bytes of data to display
            "timestamp_format": "%H:%M:%S.%f"  # Timestamp format
        }
    
    def set_filter(self, **kwargs):
        """
        Set packet capture filters.
        
        Args:
            protocol: Protocol to filter (TCP, UDP, ICMP, etc.)
            source_ip: Source IP address to filter
            dest_ip: Destination IP address to filter
            port: Port number to filter
            min_size: Minimum packet size
            max_size: Maximum packet size
        """
        for key, value in kwargs.items():
            if key in self.filters:
                self.filters[key] = value
                self.logger.info(f"Set filter {key} = {value}")
    
    def set_display_options(self, **kwargs):
        """
        Configure packet display options.
        
        Args:
            show_ethernet: Show Ethernet frame information
            show_ip: Show IP packet information
            show_transport: Show TCP/UDP information
            show_data: Show packet payload data
            max_data_bytes: Maximum bytes of payload to display
        """
        for key, value in kwargs.items():
            if key in self.display_options:
                self.display_options[key] = value
                self.logger.info(f"Set display option {key} = {value}")
    
    def start_capture(self, duration: Optional[float] = None):
        """
        Start capturing network packets.
        
        Args:
            duration: How long to capture (seconds), or None for unlimited
        """
        if self.running:
            self.logger.warning("Capture already running")
            return
        
        self.running = True
        self.stats["capture_start"] = time.time()
        self.captured_packets.clear()
        
        # Reset statistics
        for key in self.stats:
            if key not in ["capture_start"]:
                self.stats[key] = 0
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(duration,),
            daemon=True
        )
        self.capture_thread.start()
        
        self.logger.info("Packet capture started")
        if duration:
            self.logger.info(f"Capture will run for {duration} seconds")
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.running:
            return
        
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=1)
        
        if self.stats["capture_start"]:
            self.stats["capture_duration"] = time.time() - self.stats["capture_start"]
        
        self.logger.info("Packet capture stopped")
        self._print_capture_summary()
    
    def _capture_loop(self, duration: Optional[float] = None):
        """
        Main packet capture loop.
        
        This continuously monitors for network packets and processes them.
        """
        end_time = time.time() + duration if duration else None
        
        while self.running:
            try:
                # Check if duration has elapsed
                if end_time and time.time() >= end_time:
                    break
                
                # Try to capture a packet from the physical layer
                raw_data = self.stack.physical_layer.receive(timeout=0.1)
                
                if raw_data:
                    self._process_captured_packet(raw_data)
                
            except Exception as e:
                self.logger.error(f"Error in capture loop: {e}")
                time.sleep(0.1)
        
        self.running = False
    
    def _process_captured_packet(self, raw_data: bytes):
        """
        Process a captured packet through all protocol layers.
        
        Args:
            raw_data: Raw packet bytes from physical layer
        """
        try:
            packet_info = {
                "timestamp": datetime.now(),
                "size": len(raw_data),
                "raw_data": raw_data,
                "layers": {}
            }
            
            # Process Ethernet frame (Data Link Layer)
            ethernet_frame = EthernetFrame.from_bytes(raw_data)
            if ethernet_frame:
                packet_info["layers"]["ethernet"] = {
                    "src_mac": ethernet_frame.src_mac,
                    "dest_mac": ethernet_frame.dest_mac,
                    "ethertype": f"0x{ethernet_frame.ethertype:04x}",
                    "payload_size": len(ethernet_frame.payload)
                }
                self.stats["ethernet_frames"] += 1
                
                # Process IP packet (Network Layer)
                if ethernet_frame.ethertype == 0x0800:  # IPv4
                    ip_packet = IPPacket.from_bytes(ethernet_frame.payload)
                    if ip_packet:
                        packet_info["layers"]["ip"] = {
                            "version": ip_packet.version,
                            "src_ip": ip_packet.source_ip,
                            "dest_ip": ip_packet.dest_ip,
                            "protocol": ip_packet.protocol,
                            "ttl": ip_packet.ttl,
                            "total_length": ip_packet.total_length,
                            "identification": ip_packet.identification
                        }
                        self.stats["ip_packets"] += 1
                        
                        # Process Transport Layer
                        self._process_transport_layer(packet_info, ip_packet)
            
            # Apply filters
            if self._packet_matches_filters(packet_info):
                self.captured_packets.append(packet_info)
                self.stats["total_packets"] += 1
                
                # Display packet if real-time display is enabled
                self._display_packet(packet_info)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _process_transport_layer(self, packet_info: dict, ip_packet: IPPacket):
        """
        Process transport layer protocols (TCP, UDP, ICMP).
        
        Args:
            packet_info: Packet information dictionary to update
            ip_packet: Parsed IP packet
        """
        if ip_packet.protocol == 6:  # TCP
            tcp_info = self._parse_tcp_header(ip_packet.data)
            if tcp_info:
                packet_info["layers"]["tcp"] = tcp_info
                self.stats["tcp_packets"] += 1
        
        elif ip_packet.protocol == 17:  # UDP
            udp_info = self._parse_udp_header(ip_packet.data)
            if udp_info:
                packet_info["layers"]["udp"] = udp_info
                self.stats["udp_packets"] += 1
        
        elif ip_packet.protocol == 1:  # ICMP
            icmp_info = self._parse_icmp_header(ip_packet.data)
            if icmp_info:
                packet_info["layers"]["icmp"] = icmp_info
                self.stats["icmp_packets"] += 1
        
        else:
            self.stats["other_packets"] += 1
    
    def _parse_tcp_header(self, data: bytes) -> Optional[dict]:
        """Parse TCP header from packet data."""
        if len(data) < 20:  # Minimum TCP header size
            return None
        
        import struct
        try:
            header = struct.unpack('!HHLLBBHHH', data[:20])
            src_port, dest_port, seq_num, ack_num, header_len_flags, \
            flags, window_size, checksum, urgent_ptr = header
            
            header_length = (header_len_flags >> 4) * 4
            
            return {
                "src_port": src_port,
                "dest_port": dest_port,
                "sequence_number": seq_num,
                "ack_number": ack_num,
                "header_length": header_length,
                "flags": {
                    "SYN": bool(flags & 0x02),
                    "ACK": bool(flags & 0x10),
                    "FIN": bool(flags & 0x01),
                    "RST": bool(flags & 0x04),
                    "PSH": bool(flags & 0x08),
                    "URG": bool(flags & 0x20)
                },
                "window_size": window_size,
                "checksum": f"0x{checksum:04x}",
                "payload_size": len(data) - header_length
            }
        except Exception:
            return None
    
    def _parse_udp_header(self, data: bytes) -> Optional[dict]:
        """Parse UDP header from packet data."""
        if len(data) < 8:  # UDP header size
            return None
        
        import struct
        try:
            header = struct.unpack('!HHHH', data[:8])
            src_port, dest_port, length, checksum = header
            
            return {
                "src_port": src_port,
                "dest_port": dest_port,
                "length": length,
                "checksum": f"0x{checksum:04x}",
                "payload_size": length - 8
            }
        except Exception:
            return None
    
    def _parse_icmp_header(self, data: bytes) -> Optional[dict]:
        """Parse ICMP header from packet data."""
        if len(data) < 8:  # Minimum ICMP header size
            return None
        
        import struct
        try:
            header = struct.unpack('!BBHI', data[:8])
            icmp_type, code, checksum, rest = header
            
            # Map ICMP types to human-readable names
            type_names = {
                0: "Echo Reply",
                3: "Destination Unreachable", 
                8: "Echo Request",
                11: "Time Exceeded",
                12: "Parameter Problem"
            }
            
            return {
                "type": icmp_type,
                "type_name": type_names.get(icmp_type, f"Type {icmp_type}"),
                "code": code,
                "checksum": f"0x{checksum:04x}",
                "payload_size": len(data) - 8
            }
        except Exception:
            return None
    
    def _packet_matches_filters(self, packet_info: dict) -> bool:
        """
        Check if a packet matches the current filters.
        
        Args:
            packet_info: Packet information to check
            
        Returns:
            True if packet matches filters, False otherwise
        """
        # Size filters
        size = packet_info["size"]
        if size < self.filters["min_size"] or size > self.filters["max_size"]:
            return False
        
        # IP address filters
        if "ip" in packet_info["layers"]:
            ip_layer = packet_info["layers"]["ip"]
            
            if self.filters["source_ip"] and ip_layer["src_ip"] != self.filters["source_ip"]:
                return False
            
            if self.filters["dest_ip"] and ip_layer["dest_ip"] != self.filters["dest_ip"]:
                return False
        
        # Protocol filter
        if self.filters["protocol"]:
            protocol = self.filters["protocol"].upper()
            if protocol not in packet_info["layers"]:
                return False
        
        # Port filter
        if self.filters["port"]:
            port_found = False
            for layer_name in ["tcp", "udp"]:
                if layer_name in packet_info["layers"]:
                    layer = packet_info["layers"][layer_name]
                    if (layer["src_port"] == self.filters["port"] or 
                        layer["dest_port"] == self.filters["port"]):
                        port_found = True
                        break
            
            if not port_found:
                return False
        
        return True
    
    def _display_packet(self, packet_info: dict):
        """
        Display packet information in a formatted way.
        
        Args:
            packet_info: Packet information to display
        """
        timestamp = packet_info["timestamp"].strftime(self.display_options["timestamp_format"])
        print(f"\n[{timestamp}] Packet #{self.stats['total_packets']} ({packet_info['size']} bytes)")
        print("-" * 70)
        
        # Ethernet layer
        if self.display_options["show_ethernet"] and "ethernet" in packet_info["layers"]:
            eth = packet_info["layers"]["ethernet"]
            print(f"Ethernet: {eth['src_mac']} → {eth['dest_mac']} (Type: {eth['ethertype']})")
        
        # IP layer
        if self.display_options["show_ip"] and "ip" in packet_info["layers"]:
            ip = packet_info["layers"]["ip"]
            protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
            protocol_name = protocol_names.get(ip["protocol"], f"Protocol {ip['protocol']}")
            print(f"IP: {ip['src_ip']} → {ip['dest_ip']} ({protocol_name}, TTL={ip['ttl']})")
        
        # Transport layer
        if self.display_options["show_transport"]:
            if "tcp" in packet_info["layers"]:
                tcp = packet_info["layers"]["tcp"]
                flags = []
                for flag, value in tcp["flags"].items():
                    if value:
                        flags.append(flag)
                
                flag_str = ",".join(flags) if flags else "None"
                print(f"TCP: Port {tcp['src_port']} → {tcp['dest_port']} [Flags: {flag_str}]")
                print(f"     Seq={tcp['sequence_number']}, Ack={tcp['ack_number']}, Win={tcp['window_size']}")
            
            elif "udp" in packet_info["layers"]:
                udp = packet_info["layers"]["udp"]
                print(f"UDP: Port {udp['src_port']} → {udp['dest_port']} (Length: {udp['length']})")
            
            elif "icmp" in packet_info["layers"]:
                icmp = packet_info["layers"]["icmp"]
                print(f"ICMP: {icmp['type_name']} (Type={icmp['type']}, Code={icmp['code']})")
        
        # Packet data preview
        if self.display_options["show_data"] and packet_info["raw_data"]:
            data_preview = packet_info["raw_data"][:self.display_options["max_data_bytes"]]
            hex_dump = " ".join(f"{b:02x}" for b in data_preview)
            print(f"Data: {hex_dump}")
            if len(packet_info["raw_data"]) > self.display_options["max_data_bytes"]:
                print("      ...")
    
    def _print_capture_summary(self):
        """Print a summary of the capture session."""
        print("\n" + "="*60)
        print("                 CAPTURE SUMMARY")
        print("="*60)
        
        duration = self.stats.get("capture_duration", 0)
        print(f"Capture Duration: {duration:.2f} seconds")
        print(f"Total Packets: {self.stats['total_packets']}")
        
        if self.stats['total_packets'] > 0:
            print(f"Packets per second: {self.stats['total_packets'] / max(duration, 0.001):.1f}")
        
        print("\nProtocol Breakdown:")
        print(f"  Ethernet frames: {self.stats['ethernet_frames']}")
        print(f"  IP packets: {self.stats['ip_packets']}")
        print(f"  TCP packets: {self.stats['tcp_packets']}")
        print(f"  UDP packets: {self.stats['udp_packets']}")
        print(f"  ICMP packets: {self.stats['icmp_packets']}")
        print(f"  Other packets: {self.stats['other_packets']}")
        
        print("\nActive Filters:")
        active_filters = {k: v for k, v in self.filters.items() if v is not None and v != 0 and v != 65535}
        if active_filters:
            for key, value in active_filters.items():
                print(f"  {key}: {value}")
        else:
            print("  None")
    
    def save_capture(self, filename: str, format_type: str = "json"):
        """
        Save captured packets to a file.
        
        Args:
            filename: Output filename
            format_type: Format to save (json, csv, txt)
        """
        try:
            if format_type == "json":
                self._save_as_json(filename)
            elif format_type == "csv":
                self._save_as_csv(filename)
            elif format_type == "txt":
                self._save_as_text(filename)
            else:
                raise ValueError(f"Unknown format: {format_type}")
            
            self.logger.info(f"Capture saved to {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to save capture: {e}")
    
    def _save_as_json(self, filename: str):
        """Save capture data as JSON."""
        data = {
            "capture_info": {
                "start_time": self.stats["capture_start"],
                "duration": self.stats["capture_duration"],
                "total_packets": self.stats["total_packets"]
            },
            "statistics": self.stats,
            "filters": self.filters,
            "packets": []
        }
        
        for packet in self.captured_packets:
            packet_data = packet.copy()
            # Convert timestamp to string for JSON serialization
            packet_data["timestamp"] = packet["timestamp"].isoformat()
            # Convert raw data to hex string
            packet_data["raw_data"] = packet["raw_data"].hex()
            data["packets"].append(packet_data)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _save_as_csv(self, filename: str):
        """Save capture data as CSV."""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Timestamp", "Size", "Src MAC", "Dest MAC", "EtherType",
                "Src IP", "Dest IP", "Protocol", "Src Port", "Dest Port"
            ])
            
            # Write packet data
            for packet in self.captured_packets:
                row = [
                    packet["timestamp"].isoformat(),
                    packet["size"],
                    packet["layers"].get("ethernet", {}).get("src_mac", ""),
                    packet["layers"].get("ethernet", {}).get("dest_mac", ""),
                    packet["layers"].get("ethernet", {}).get("ethertype", ""),
                    packet["layers"].get("ip", {}).get("src_ip", ""),
                    packet["layers"].get("ip", {}).get("dest_ip", ""),
                    packet["layers"].get("ip", {}).get("protocol", ""),
                    packet["layers"].get("tcp", packet["layers"].get("udp", {})).get("src_port", ""),
                    packet["layers"].get("tcp", packet["layers"].get("udp", {})).get("dest_port", "")
                ]
                writer.writerow(row)
    
    def _save_as_text(self, filename: str):
        """Save capture data as formatted text."""
        with open(filename, 'w') as f:
            f.write("TCP/IP Stack Packet Capture\n")
            f.write("="*50 + "\n\n")
            
            f.write(f"Capture started: {datetime.fromtimestamp(self.stats['capture_start'])}\n")
            f.write(f"Duration: {self.stats['capture_duration']:.2f} seconds\n")
            f.write(f"Total packets: {self.stats['total_packets']}\n\n")
            
            for i, packet in enumerate(self.captured_packets, 1):
                f.write(f"Packet #{i} - {packet['timestamp']}\n")
                f.write(f"Size: {packet['size']} bytes\n")
                
                for layer_name, layer_data in packet["layers"].items():
                    f.write(f"{layer_name.upper()}: {layer_data}\n")
                
                f.write("\n" + "-"*40 + "\n\n")

def main():
    """Main entry point for the packet sniffer example."""
    parser = argparse.ArgumentParser(
        description="Packet Sniffer using custom TCP/IP stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --duration 30                       # Capture for 30 seconds
  %(prog)s --protocol TCP --port 80            # Capture HTTP traffic
  %(prog)s --src-ip 192.168.1.100             # Filter by source IP
  %(prog)s --save capture.json                # Save to file
        """
    )
    
    # Capture options
    parser.add_argument("--duration", type=float,
                       help="Capture duration in seconds (unlimited if not specified)")
    parser.add_argument("--interface", default="lo",
                       help="Network interface to use (default: lo)")
    
    # Filter options
    parser.add_argument("--protocol", choices=["TCP", "UDP", "ICMP"],
                       help="Filter by protocol")
    parser.add_argument("--src-ip", help="Filter by source IP address")
    parser.add_argument("--dest-ip", help="Filter by destination IP address")
    parser.add_argument("--port", type=int, help="Filter by port number")
    parser.add_argument("--min-size", type=int, default=0,
                       help="Minimum packet size filter")
    parser.add_argument("--max-size", type=int, default=65535,
                       help="Maximum packet size filter")
    
    # Display options
    parser.add_argument("--no-ethernet", action="store_true",
                       help="Don't show Ethernet frame details")
    parser.add_argument("--no-ip", action="store_true",
                       help="Don't show IP packet details")
    parser.add_argument("--no-transport", action="store_true",
                       help="Don't show transport layer details")
    parser.add_argument("--show-data", action="store_true",
                       help="Show packet payload data")
    parser.add_argument("--data-bytes", type=int, default=64,
                       help="Max bytes of payload to display (default: 64)")
    
    # Output options
    parser.add_argument("--save", help="Save capture to file")
    parser.add_argument("--format", choices=["json", "csv", "txt"], default="json",
                       help="Save format (default: json)")
    
    args = parser.parse_args()
    
    # Create and start TCP/IP stack
    print("Initializing TCP/IP stack...")
    stack = TCPIPStack(args.interface)
    
    try:
        stack.start()
        print("TCP/IP stack started successfully")
        
        # Create packet sniffer
        sniffer = PacketSniffer(stack)
        
        # Set filters
        filter_kwargs = {}
        if args.protocol:
            filter_kwargs["protocol"] = args.protocol
        if args.src_ip:
            filter_kwargs["source_ip"] = args.src_ip
        if args.dest_ip:
            filter_kwargs["dest_ip"] = args.dest_ip
        if args.port:
            filter_kwargs["port"] = args.port
        if args.min_size:
            filter_kwargs["min_size"] = args.min_size
        if args.max_size != 65535:
            filter_kwargs["max_size"] = args.max_size
        
        if filter_kwargs:
            sniffer.set_filter(**filter_kwargs)
        
        # Set display options
        display_kwargs = {
            "show_ethernet": not args.no_ethernet,
            "show_ip": not args.no_ip,
            "show_transport": not args.no_transport,
            "show_data": args.show_data,
            "max_data_bytes": args.data_bytes
        }
        sniffer.set_display_options(**display_kwargs)
        
        # Start capture
        print("\nStarting packet capture...")
        if args.duration:
            print(f"Capturing for {args.duration} seconds...")
        else:
            print("Capturing until interrupted (Ctrl+C to stop)...")
        
        sniffer.start_capture(args.duration)
        
        # Wait for capture to complete
        try:
            while sniffer.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        
        sniffer.stop_capture()
        
        # Save capture if requested
        if args.save:
            print(f"\nSaving capture to {args.save}...")
            sniffer.save_capture(args.save, args.format)
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stack.stop()
        print("TCP/IP stack stopped")

if __name__ == "__main__":
    main()