"""
TCP/IP Stack Implementation

A comprehensive educational implementation of the TCP/IP protocol stack,
demonstrating how network protocols work from the physical layer up to
the application layer.

This package provides a complete networking stack that can:
- Handle packet transmission and reception
- Route packets between networks  
- Provide reliable (TCP) and fast (UDP) transport
- Support HTTP and custom application protocols
- Monitor and analyze network traffic in real-time

The implementation is designed for learning and demonstration purposes,
showcasing fundamental networking concepts in clean, well-documented code.
"""

# Import all the core components that make up our TCP/IP stack
from .physical_layer import PhysicalLayer
from .data_link_layer import DataLinkLayer, EthernetFrame
from .network_layer import NetworkLayer, IPPacket
from .transport_layer import TransportLayer, TCPPacket, UDPPacket, TCPConnection
from .application_layer import ApplicationLayer, HTTPRequest, HTTPResponse
from .routing import RoutingTable, Route
from .utils import (
    calculate_checksum, validate_ip_address, validate_mac_address,
    format_bytes, format_duration, create_logger
)

import logging
import threading
import time
from typing import Dict, Any, Optional, List

class TCPIPStack:
    """
    Complete TCP/IP Stack Implementation
    
    This is the main class that brings together all five layers of the
    network stack. Think of it as the "orchestra conductor" that coordinates
    all the different components to create a functioning network system.
    
    The stack handles:
    - Physical transmission (bits over the wire)
    - Frame delivery (local network communication)
    - Packet routing (internet-wide delivery)
    - Reliable transport (TCP connections)
    - Application services (HTTP, custom protocols)
    
    Example usage:
        stack = TCPIPStack("eth0")
        stack.start()
        # Now the stack is ready to send and receive network traffic
        stack.stop()
    """
    
    def __init__(self, interface: str = "lo"):
        """
        Initialize the complete TCP/IP stack.
        
        This sets up all five layers and prepares them to work together.
        Like assembling a complex machine where each part has a specific job.
        
        Args:
            interface: Network interface to use (default: loopback for safety)
        """
        self.logger = create_logger(self.__class__.__name__)
        self.interface = interface
        
        # Overall stack statistics
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections_established": 0,
            "connections_closed": 0,
            "errors": 0,
            "start_time": None,
            "uptime_seconds": 0
        }
        
        # Initialize all five layers
        self.physical_layer = PhysicalLayer(interface)
        self.data_link_layer = DataLinkLayer()
        self.network_layer = NetworkLayer()
        self.transport_layer = TransportLayer()
        self.application_layer = ApplicationLayer()
        
        # Initialize routing table
        self.routing_table = RoutingTable()
        
        # Demo traffic generator for simulation mode
        from .demo_traffic import DemoTrafficGenerator
        self.demo_traffic = DemoTrafficGenerator(self)
        
        # Control flags
        self._running = False
        self._capture_thread = None
        
        self.logger.info(f"TCP/IP Stack initialized on interface {interface}")
    
    def start(self):
        """
        Start the entire TCP/IP stack.
        
        This brings up all layers and begins processing network traffic.
        Like starting a car - all systems need to work together.
        """
        if self._running:
            self.logger.info("Stack already running")
            return
        
        try:
            # Record start time
            self.stats["start_time"] = time.time()
            
            # Start physical layer first (foundation of everything)
            self.physical_layer.start()
            
            # Check if we're in simulation mode and start demo traffic
            if hasattr(self.physical_layer, '_simulation_mode') and self.physical_layer._simulation_mode:
                self.logger.info("Starting demo traffic generator for simulation mode")
                self.demo_traffic.start()
            
            # Setup basic routing - how to reach different networks
            self.routing_table.add_route("127.0.0.0/8", "127.0.0.1", self.interface)  # Loopback
            self.routing_table.add_route("0.0.0.0/0", "127.0.0.1", self.interface)    # Default route
            
            # Start packet processing
            self.start_capture()
            
            self._running = True
            self.logger.info("TCP/IP Stack started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start stack: {e}")
            # In simulation mode, we can still continue
            if hasattr(self.physical_layer, '_simulation_mode') and self.physical_layer._simulation_mode:
                self._running = True
                self.stats["start_time"] = time.time()
                self.logger.info("Continuing in simulation mode despite errors")
                self.demo_traffic.start()
            else:
                raise
    
    def stop(self):
        """
        Stop the entire TCP/IP stack.
        
        This gracefully shuts down all layers and cleans up resources.
        Like turning off a car - everything stops in the right order.
        """
        if not self._running:
            return
        
        self._running = False
        
        # Stop demo traffic
        self.demo_traffic.stop()
        
        # Stop packet capture
        self.stop_capture()
        
        # Wait for capture thread to finish
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1)
        
        # Stop physical layer last
        self.physical_layer.stop()
        
        # Calculate uptime
        if self.stats["start_time"]:
            self.stats["uptime_seconds"] = time.time() - self.stats["start_time"]
        
        self.logger.info("TCP/IP Stack stopped")
    
    def shutdown(self):
        """
        Gracefully shutdown the stack.
        
        This is an alias for stop() that provides a more explicit
        shutdown method for applications.
        """
        self.stop()
    
    def send_packet(self, data: bytes, destination_ip: str, protocol: str = "TCP", 
                   dest_port: int = 80, source_port: int = None):
        """
        Send data through the complete TCP/IP stack.
        
        This demonstrates how data flows down through all the layers:
        Application → Transport → Network → Data Link → Physical
        
        Args:
            data: Application data to send
            destination_ip: Where to send it
            protocol: Transport protocol ("TCP" or "UDP")
            dest_port: Destination port number
            source_port: Source port (auto-assigned if None)
        """
        try:
            if not self._running:
                raise Exception("Stack not running")
            
            # Transport Layer: Add port information and reliability
            if protocol.upper() == "TCP":
                if not source_port:
                    source_port = self.transport_layer.allocate_port()
                
                tcp_packet = self.transport_layer.send_tcp_data(
                    self.transport_layer.create_tcp_connection(destination_ip, dest_port, source_port),
                    data
                )
                transport_data = tcp_packet.to_bytes()
                protocol_num = 6  # TCP protocol number
                
            elif protocol.upper() == "UDP":
                if not source_port:
                    source_port = self.transport_layer.allocate_port()
                
                udp_packet = self.transport_layer.send_udp_data(
                    source_port, destination_ip, dest_port, data
                )
                transport_data = udp_packet.to_bytes()
                protocol_num = 17  # UDP protocol number
                
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")
            
            # Network Layer: Add IP addressing and routing
            ip_packet = self.network_layer.create_packet(
                transport_data, destination_ip, protocol_num
            )
            
            # Data Link Layer: Add local network addressing
            frame_data = self.data_link_layer.create_frame(
                ip_packet.to_bytes(), destination_ip
            )
            
            # Physical Layer: Transmit over the wire
            success = self.physical_layer.send(frame_data, destination_ip)
            
            if success:
                # Update statistics
                self.stats["packets_sent"] += 1
                self.stats["bytes_sent"] += len(data)
                self.logger.debug(f"Sent {len(data)} bytes to {destination_ip}:{dest_port} via {protocol}")
            
            return success
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Failed to send packet: {e}")
            return False
    
    def start_capture(self):
        """
        Start capturing incoming packets.
        
        This runs in a separate thread to continuously monitor
        for incoming network traffic.
        """
        if self._capture_thread and self._capture_thread.is_alive():
            return
        
        self._capture_thread = threading.Thread(target=self._packet_capture_loop, daemon=True)
        self._capture_thread.start()
        self.logger.debug("Started packet capture thread")
    
    def stop_capture(self):
        """Stop packet capture."""
        # The capture loop will stop when _running becomes False
        self.logger.debug("Stopped packet capture")
    
    def _packet_capture_loop(self):
        """
        Main packet processing loop.
        
        This continuously receives packets and processes them
        up through the protocol stack.
        """
        while self._running:
            try:
                # Try to receive a packet from the physical layer
                raw_data = self.physical_layer.receive(timeout=0.1)
                
                if raw_data:
                    self._process_received_packet(raw_data)
                
            except Exception as e:
                self.logger.error(f"Error in packet capture loop: {e}")
                time.sleep(0.1)  # Brief pause to prevent tight error loop
    
    def _process_received_packet(self, raw_data: bytes):
        """
        Process a received packet up through the stack.
        
        This demonstrates how data flows up through all the layers:
        Physical → Data Link → Network → Transport → Application
        
        Args:
            raw_data: Raw packet bytes from physical layer
        """
        try:
            # Data Link Layer: Extract IP packet from frame
            ip_data = self.data_link_layer.process_frame(raw_data)
            if not ip_data:
                return  # Frame not for us or corrupted
            
            # Network Layer: Process IP packet
            packet_info = self.network_layer.process_packet(ip_data)
            if not packet_info:
                return  # Packet not for us or corrupted
            
            transport_data, source_ip, protocol = packet_info
            
            # Transport Layer: Process TCP/UDP
            if protocol == 6:  # TCP
                app_data = self.transport_layer.process_tcp_packet(transport_data, source_ip)
            elif protocol == 17:  # UDP
                udp_info = self.transport_layer.process_udp_packet(transport_data, source_ip)
                if udp_info:
                    app_data, source_port, dest_port = udp_info
                else:
                    app_data = None
            else:
                app_data = transport_data  # Unknown protocol, pass raw data
            
            # Application Layer: Process application data
            if app_data:
                # Try to process as HTTP first
                if app_data.startswith(b'GET ') or app_data.startswith(b'POST '):
                    response = self.application_layer.process_http_request(app_data, 80)
                    if response:
                        # Send HTTP response back (simplified)
                        self.logger.debug(f"Processed HTTP request from {source_ip}")
                
                # Update statistics
                self.stats["packets_received"] += 1
                self.stats["bytes_received"] += len(app_data)
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing received packet: {e}")
    
    def ping(self, destination_ip: str, count: int = 4, timeout: float = 1.0) -> Dict[str, Any]:
        """
        Send ICMP ping to test connectivity.
        
        This is like sending a "hello, are you there?" message
        to another computer and measuring how long it takes to respond.
        
        Args:
            destination_ip: Target to ping
            count: Number of ping packets to send
            timeout: How long to wait for each response
            
        Returns:
            Dictionary with ping results
        """
        results = {
            "destination": destination_ip,
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss": 0.0,
            "min_time": float('inf'),
            "max_time": 0.0,
            "avg_time": 0.0,
            "times": []
        }
        
        self.logger.info(f"PING {destination_ip} ({count} packets)")
        
        for i in range(count):
            ping_result = self.network_layer.ping(destination_ip, timeout)
            results["packets_sent"] += 1
            
            if ping_result["success"]:
                results["packets_received"] += 1
                time_ms = ping_result["time_ms"]
                results["times"].append(time_ms)
                results["min_time"] = min(results["min_time"], time_ms)
                results["max_time"] = max(results["max_time"], time_ms)
                
                self.logger.info(f"64 bytes from {destination_ip}: time={time_ms:.1f}ms")
            else:
                self.logger.warning(f"Request timeout for icmp_seq {i+1}")
            
            # Wait between pings
            if i < count - 1:
                time.sleep(1.0)
        
        # Calculate final statistics
        if results["packets_received"] > 0:
            results["avg_time"] = sum(results["times"]) / len(results["times"])
            if results["min_time"] == float('inf'):
                results["min_time"] = 0.0
        
        results["packet_loss"] = (1.0 - results["packets_received"] / results["packets_sent"]) * 100
        
        self.logger.info(f"--- {destination_ip} ping statistics ---")
        self.logger.info(f"{results['packets_sent']} packets transmitted, {results['packets_received']} received, {results['packet_loss']:.1f}% packet loss")
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics from all layers.
        
        This provides a complete picture of network activity
        across the entire stack.
        """
        # Calculate current uptime
        current_uptime = 0
        if self._running and self.stats["start_time"]:
            current_uptime = time.time() - self.stats["start_time"]
        
        return {
            "stack": {
                **self.stats,
                "running": self._running,
                "interface": self.interface,
                "uptime_seconds": current_uptime
            },
            "physical": self.physical_layer.get_statistics(),
            "data_link": self.data_link_layer.get_statistics(),
            "network": self.network_layer.get_statistics(),
            "transport": self.transport_layer.get_statistics(),
            "application": self.application_layer.get_statistics(),
            "routing": self.routing_table.get_statistics()
        }
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current stack status.
        
        This provides a quick overview of whether the stack
        is running and healthy.
        """
        return {
            "running": self._running,
            "interface": self.interface,
            "simulation_mode": getattr(self.physical_layer, '_simulation_mode', False),
            "uptime": time.time() - self.stats["start_time"] if self._running and self.stats["start_time"] else 0,
            "total_packets": self.stats["packets_sent"] + self.stats["packets_received"],
            "error_rate": self.stats["errors"] / max(1, self.stats["packets_sent"] + self.stats["packets_received"])
        }
    
    def is_running(self) -> bool:
        """Check if the stack is currently running."""
        return self._running
    
    def __enter__(self):
        """Context manager entry - start the stack."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - stop the stack."""
        self.stop()

# Package version and metadata
__version__ = "1.0.0"
__author__ = "TCP/IP Stack Implementation Team"
__description__ = "Educational implementation of the TCP/IP protocol stack"

# Export main classes for easy importing
__all__ = [
    "TCPIPStack",
    "PhysicalLayer",
    "DataLinkLayer", 
    "NetworkLayer",
    "TransportLayer",
    "ApplicationLayer",
    "RoutingTable",
    "EthernetFrame",
    "IPPacket", 
    "TCPPacket",
    "UDPPacket",
    "HTTPRequest",
    "HTTPResponse",
    "Route"
]