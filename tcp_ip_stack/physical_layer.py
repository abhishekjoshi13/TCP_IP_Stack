"""
Physical Layer Implementation

This module represents the lowest layer of our network stack - the physical layer.
In a real network, this would handle actual electrical signals, radio waves, or fiber optics.
For our educational implementation, we simulate this using software.

Think of this as the "highway" that carries all network traffic.
"""

import socket
import logging
import threading
import time
from typing import Optional

class PhysicalLayer:
    """
    The Physical Layer - Foundation of Network Communication
    
    This layer simulates how data travels as electrical signals over network cables
    or wireless transmissions. In our demonstration, we use the computer's loopback
    interface to simulate a network connection.
    
    Key Responsibilities:
    - Converting data into transmittable signals (bits)
    - Managing the physical connection
    - Detecting transmission errors
    - Controlling access to the transmission medium
    """
    
    def __init__(self, interface: str = "lo"):
        """
        Set up our physical layer simulation.
        
        Args:
            interface: Which network interface to use (default: loopback for safety)
        """
        # Set up logging so we can see what's happening
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Store configuration
        self.interface = interface
        self.socket = None
        self._running = False
        self._simulation_mode = False
        self._lock = threading.Lock()  # Prevent multiple threads from conflicting
        
        # Keep track of our transmission statistics
        self.stats = {
            "frames_sent": 0,
            "frames_received": 0, 
            "bytes_transmitted": 0,
            "transmission_errors": 0
        }
        
        self.logger.info(f"Physical layer initialized on interface {interface}")
    
    def start(self):
        """
        Start the physical layer and establish our connection to the network.
        
        This tries to create a real raw socket first (requires admin privileges),
        but gracefully falls back to simulation mode if that fails.
        """
        if self._running:
            self.logger.info("Physical layer already running")
            return
        
        try:
            # First, try to create a real raw socket for authentic networking
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.socket.bind(("127.0.0.1", 0))
                self.logger.info("Physical layer started with real raw sockets")
                self._simulation_mode = False
                
            except (PermissionError, OSError) as e:
                # No worries! We'll use simulation mode instead
                self.logger.info("Raw socket requires admin privileges - switching to simulation mode")
                self.socket = None
                self._simulation_mode = True
            
            self._running = True
            
            if self._simulation_mode:
                self.logger.info("Simulation mode active - all networking concepts demonstrated without raw sockets")
            
        except Exception as e:
            # Even if everything fails, we can still demonstrate networking concepts
            self.logger.warning(f"Socket creation failed, using full simulation mode: {e}")
            self.socket = None
            self._running = True
            self._simulation_mode = True
    
    def stop(self):
        """
        Shut down the physical layer and clean up resources.
        
        This is like unplugging a network cable - it stops all communication.
        """
        self._running = False
        
        if self.socket:
            try:
                self.socket.close()
                self.logger.info("Raw socket closed successfully")
            except Exception as e:
                self.logger.error(f"Error closing socket: {e}")
            finally:
                self.socket = None
        
        self.logger.info("Physical layer stopped")
    
    def send(self, frame_data: bytes, destination: str = "127.0.0.1") -> bool:
        """
        Transmit data over the physical medium.
        
        This simulates how network cards send electrical signals carrying our data.
        In reality, this would involve complex signal processing and error correction.
        
        Args:
            frame_data: The raw bytes to transmit
            destination: Where to send the data
            
        Returns:
            True if transmission successful, False otherwise
        """
        if not self._running:
            self.logger.error("Cannot send - physical layer not running")
            return False
        
        # Use thread lock to prevent conflicts during transmission
        with self._lock:
            try:
                # Simulate the time it takes to physically transmit data
                self._simulate_transmission_delay(len(frame_data))
                
                if self._simulation_mode:
                    # In simulation mode, we log the transmission for demonstration
                    self._simulate_transmission(frame_data, destination)
                else:
                    # With raw sockets, we'd actually send the data
                    self.socket.sendto(frame_data, (destination, 0))
                
                # Update our statistics
                self.stats["frames_sent"] += 1
                self.stats["bytes_transmitted"] += len(frame_data)
                
                self.logger.debug(f"Successfully transmitted {len(frame_data)} bytes to {destination}")
                return True
                
            except Exception as e:
                # Handle transmission errors (like cable disconnection)
                self.stats["transmission_errors"] += 1
                self.logger.error(f"Transmission failed: {e}")
                return False
    
    def receive(self, timeout: float = 1.0) -> Optional[bytes]:
        """
        Listen for incoming data on the physical medium.
        
        This simulates how network cards detect and capture electrical signals
        from the network and convert them back into digital data.
        
        Args:
            timeout: How long to wait for data (seconds)
            
        Returns:
            Received data bytes, or None if no data received
        """
        if not self._running:
            return None
        
        if self._simulation_mode:
            # In simulation mode, we can simulate receiving data
            return self._simulate_reception(timeout)
        
        try:
            # Set socket timeout
            self.socket.settimeout(timeout)
            
            # Try to receive data
            data, address = self.socket.recvfrom(4096)
            
            # Update statistics
            self.stats["frames_received"] += 1
            
            self.logger.debug(f"Received {len(data)} bytes from {address}")
            return data
            
        except socket.timeout:
            # No data received within timeout - this is normal
            return None
        except Exception as e:
            self.logger.error(f"Reception error: {e}")
            return None
    
    def _simulate_transmission_delay(self, data_size: int):
        """
        Simulate the physical time required to transmit data.
        
        Real networks have transmission delays based on:
        - Distance (speed of light limitations)
        - Bandwidth (how fast we can send bits)
        - Processing time in network equipment
        """
        # Simulate bandwidth of 1 Gbps (about 1 microsecond per 1000 bytes)
        delay = data_size / 1000000.0  # Very small delay for simulation
        if delay > 0.001:  # Cap at 1ms for interactive experience
            delay = 0.001
        time.sleep(delay)
    
    def _simulate_transmission(self, data: bytes, destination: str):
        """
        Simulate the physical transmission process.
        
        In reality, this would involve:
        - Converting digital data to electrical/optical signals
        - Adding error correction codes
        - Modulating the signal for transmission
        - Detecting and handling collisions
        """
        self.logger.debug(f"SIMULATION: Transmitting {len(data)} bytes to {destination}")
        
        # Simulate occasional transmission errors (about 0.01% failure rate)
        import random
        if random.random() < 0.0001:
            self.stats["transmission_errors"] += 1
            raise Exception("Simulated transmission error (cable noise)")
    
    def _simulate_reception(self, timeout: float) -> Optional[bytes]:
        """
        Simulate receiving data from the network.
        
        In simulation mode, we can demonstrate the concept of receiving
        network frames without actually having network traffic.
        """
        # For now, return None (no data) - in a full simulation,
        # this could return simulated packets from other layers
        return None
    
    def get_statistics(self) -> dict:
        """
        Get current transmission statistics.
        
        These stats help network administrators monitor:
        - How much data is being transmitted
        - Error rates (indicating cable or interference problems)
        - Connection health and performance
        """
        return {
            **self.stats,
            "is_running": self._running,
            "simulation_mode": self._simulation_mode,
            "interface": self.interface
        }
    
    def is_running(self) -> bool:
        """Check if the physical layer is currently operational."""
        return self._running