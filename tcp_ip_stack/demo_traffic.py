"""
Demo Traffic Generator

This module generates realistic network traffic patterns for demonstration
when raw sockets are not available. It simulates the kind of network
activity you'd see on a real network, helping visualize how the TCP/IP
stack processes different types of communication.

Think of this as a "network simulator" that creates fake but realistic
traffic to show how the protocols work together.
"""

import threading
import time
import random
import logging
from typing import Optional

class DemoTrafficGenerator:
    """
    Realistic Network Traffic Simulator
    
    This class generates various types of network traffic that you would
    typically see on a real network, including:
    
    - HTTP web browsing (GET, POST requests to websites)
    - SSH secure shell connections (remote server access)
    - DNS domain name lookups (converting names to IP addresses)
    - ICMP ping messages (network connectivity testing)
    - Email protocols (SMTP, POP3, IMAP)
    - File transfers (FTP, SFTP)
    
    The traffic is simulated but follows realistic patterns and timing
    that help demonstrate how different protocols behave.
    """
    
    def __init__(self, stack):
        """
        Initialize the demo traffic generator.
        
        Args:
            stack: Reference to the TCP/IP stack instance
        """
        self.stack = stack
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Traffic generation settings
        self.traffic_interval = (0.5, 3.0)  # Random interval between packets
        self.burst_probability = 0.1        # Chance of traffic bursts
        self.error_probability = 0.05       # Chance of simulated errors
        
        # Pre-defined traffic patterns for realism
        self.traffic_patterns = {
            'web_browsing': 0.40,    # 40% of traffic
            'ssh_connections': 0.20,  # 20% of traffic  
            'dns_queries': 0.25,     # 25% of traffic
            'icmp_messages': 0.10,   # 10% of traffic
            'email_protocols': 0.05  # 5% of traffic
        }
        
    def start(self):
        """
        Start generating realistic demo traffic.
        
        This begins the background process that continuously creates
        network activity to demonstrate protocol operation.
        """
        if self.running:
            self.logger.warning("Demo traffic generator already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._traffic_generation_loop, daemon=True)
        self.thread.start()
        self.logger.info("Demo traffic generator started")
        
    def stop(self):
        """
        Stop generating demo traffic.
        
        This cleanly shuts down the traffic generation process.
        """
        if not self.running:
            return
            
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        self.logger.info("Demo traffic generator stopped")
        
    def _traffic_generation_loop(self):
        """
        Main loop that generates realistic network traffic patterns.
        
        This continuously creates different types of network activity
        based on realistic usage patterns and timing.
        """
        packet_count = 0
        last_burst_time = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Determine if we should generate a traffic burst
                if (current_time - last_burst_time > 30 and 
                    random.random() < self.burst_probability):
                    self._generate_traffic_burst()
                    last_burst_time = current_time
                
                # Generate regular traffic based on patterns
                traffic_type = self._select_traffic_type()
                
                if traffic_type == 'web_browsing':
                    self._simulate_web_traffic(packet_count)
                elif traffic_type == 'ssh_connections':
                    self._simulate_ssh_traffic(packet_count)
                elif traffic_type == 'dns_queries':
                    self._simulate_dns_traffic(packet_count)
                elif traffic_type == 'icmp_messages':
                    self._simulate_icmp_traffic(packet_count)
                elif traffic_type == 'email_protocols':
                    self._simulate_email_traffic(packet_count)
                
                # Update stack statistics with simulated traffic
                self._update_stack_statistics()
                
                packet_count += 1
                
                # Wait before generating next packet
                interval = random.uniform(*self.traffic_interval)
                time.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"Error in traffic generation loop: {e}")
                time.sleep(1)  # Brief pause before retrying
                
    def _select_traffic_type(self) -> str:
        """
        Select the type of traffic to generate based on realistic patterns.
        
        This uses weighted random selection to simulate the typical
        distribution of traffic types on a real network.
        
        Returns:
            Traffic type string
        """
        rand = random.random()
        cumulative = 0
        
        for traffic_type, probability in self.traffic_patterns.items():
            cumulative += probability
            if rand <= cumulative:
                return traffic_type
        
        return 'web_browsing'  # Default fallback
    
    def _simulate_web_traffic(self, packet_id: int):
        """
        Simulate HTTP/HTTPS web browsing traffic.
        
        This generates realistic web requests like you'd see when
        browsing websites, including different HTTP methods and
        various destination servers.
        """
        # Realistic source IP ranges (private networks)
        source_networks = ["192.168.1", "10.0.0", "172.16.0"]
        source_network = random.choice(source_networks)
        source_ip = f"{source_network}.{random.randint(10, 250)}"
        
        # Realistic web server IP ranges (public internet)
        dest_ip = f"203.0.113.{random.randint(1, 254)}"  # RFC 5737 test range
        
        # Common HTTP methods and their relative frequency
        methods = ["GET"] * 70 + ["POST"] * 20 + ["PUT"] * 5 + ["DELETE"] * 5
        method = random.choice(methods)
        
        # Realistic web paths
        paths = ["/", "/index.html", "/api/data", "/login", "/dashboard", 
                "/images/logo.png", "/css/style.css", "/js/app.js", "/favicon.ico"]
        path = random.choice(paths)
        
        # Simulate different types of web activity
        if method == "GET":
            if path.endswith(('.png', '.jpg', '.css', '.js')):
                activity = f"Loading resource: {path}"
            else:
                activity = f"Browsing page: {path}"
        elif method == "POST":
            activity = f"Submitting form data to {path}"
        elif method == "PUT":
            activity = f"Uploading data to {path}"
        else:  # DELETE
            activity = f"Deleting resource: {path}"
        
        self.logger.info(f"HTTP: {method} {path} from {source_ip} to {dest_ip}")
        
        # Simulate response time and data transfer
        if path.endswith(('.png', '.jpg')):
            # Images are larger
            simulated_bytes = random.randint(5000, 50000)
        elif method == "POST":
            # Form submissions typically small
            simulated_bytes = random.randint(100, 2000)
        else:
            # Regular web pages
            simulated_bytes = random.randint(500, 10000)
            
        # Add some variability to simulate network conditions
        response_time = random.uniform(0.050, 0.500)  # 50ms to 500ms
        
    def _simulate_ssh_traffic(self, packet_id: int):
        """
        Simulate SSH (Secure Shell) connection traffic.
        
        SSH is used for secure remote access to servers. This simulates
        the encrypted traffic patterns you'd see during remote administration.
        """
        # SSH typically uses private network ranges
        source_ip = f"10.0.0.{random.randint(1, 254)}"
        dest_ip = f"10.0.0.{random.randint(1, 254)}"
        
        # SSH connection activities
        activities = [
            "Authentication handshake",
            "Terminal session data", 
            "File transfer (SCP)",
            "Port forwarding setup",
            "Command execution",
            "Heartbeat/keepalive"
        ]
        
        activity = random.choice(activities)
        
        self.logger.info(f"SSH: Secure connection from {source_ip} to {dest_ip}:22")
        
        # SSH traffic is typically small, encrypted packets
        simulated_bytes = random.randint(64, 1500)
        
    def _simulate_dns_traffic(self, packet_id: int):
        """
        Simulate DNS (Domain Name System) traffic.
        
        DNS translates human-readable domain names into IP addresses.
        This simulates the constant stream of DNS queries that happen
        during normal internet usage.
        """
        # Client making DNS query
        source_ip = f"172.16.0.{random.randint(1, 254)}"
        
        # Common DNS servers
        dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9"]
        dns_server = random.choice(dns_servers)
        
        # Popular domains that might be queried
        domains = [
            "google.com", "facebook.com", "youtube.com", "amazon.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
            "wikipedia.org", "reddit.com", "twitter.com", "linkedin.com",
            "example.com", "test.local", "internal.company.com"
        ]
        
        domain = random.choice(domains)
        
        # DNS query types
        query_types = ["A", "AAAA", "MX", "CNAME", "TXT", "NS"]
        query_type = random.choice(query_types)
        
        self.logger.info(f"DNS: Query for {domain} from {source_ip} to {dns_server}")
        
        # DNS packets are typically very small
        simulated_bytes = random.randint(32, 512)
        
    def _simulate_icmp_traffic(self, packet_id: int):
        """
        Simulate ICMP (Internet Control Message Protocol) traffic.
        
        ICMP is used for network diagnostics and error reporting.
        This includes ping messages, error notifications, and
        network troubleshooting traffic.
        """
        source_ip = f"192.168.0.{random.randint(1, 254)}"
        dest_ip = f"192.168.0.{random.randint(1, 254)}"
        
        # Different types of ICMP messages
        icmp_types = [
            "Echo Request",      # Ping request
            "Echo Reply",        # Ping response  
            "Dest Unreachable",  # Network error
            "TTL Exceeded",      # Routing loop/long path
            "Redirect",          # Routing optimization
            "Timestamp Request", # Time synchronization
        ]
        
        icmp_type = random.choice(icmp_types)
        
        self.logger.info(f"ICMP: {icmp_type} from {source_ip} to {dest_ip}")
        
        # ICMP messages are typically small
        simulated_bytes = random.randint(28, 84)  # Minimum ICMP + some data
        
    def _simulate_email_traffic(self, packet_id: int):
        """
        Simulate email protocol traffic (SMTP, POP3, IMAP).
        
        This represents the traffic generated by email clients
        sending and receiving messages.
        """
        source_ip = f"10.1.1.{random.randint(10, 100)}"
        
        # Email servers typically have dedicated IP ranges
        email_server = f"mail.{random.randint(1, 10)}.example.com"
        server_ip = f"74.125.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        # Email protocols and their typical ports
        protocols = [
            ("SMTP", 25, "Sending email"),
            ("SMTP", 587, "Sending email (submission)"), 
            ("POP3", 110, "Downloading email"),
            ("IMAP", 143, "Syncing email"),
            ("SMTPS", 465, "Sending email (SSL)"),
            ("IMAPS", 993, "Syncing email (SSL)")
        ]
        
        protocol, port, activity = random.choice(protocols)
        
        self.logger.info(f"{protocol}: {activity} from {source_ip} to {server_ip}:{port}")
        
        # Email traffic varies greatly in size
        if "Downloading" in activity or "Syncing" in activity:
            # Receiving emails can be large
            simulated_bytes = random.randint(1000, 25000)
        else:
            # Sending emails typically smaller
            simulated_bytes = random.randint(500, 5000)
    
    def _generate_traffic_burst(self):
        """
        Simulate a burst of network activity.
        
        This represents periods of high network usage, such as:
        - Large file downloads
        - Video streaming
        - Software updates
        - Backup operations
        """
        burst_duration = random.uniform(5, 15)  # 5-15 second burst
        burst_start = time.time()
        
        self.logger.info(f"Generating traffic burst for {burst_duration:.1f} seconds")
        
        while time.time() - burst_start < burst_duration and self.running:
            # Generate multiple packets rapidly
            for _ in range(random.randint(3, 8)):
                traffic_type = self._select_traffic_type()
                if traffic_type == 'web_browsing':
                    self._simulate_large_download()
                elif traffic_type == 'ssh_connections':
                    self._simulate_file_transfer()
                else:
                    # Regular traffic during burst
                    self._simulate_web_traffic(0)
                    
            time.sleep(0.1)  # Brief pause between burst packets
    
    def _simulate_large_download(self):
        """Simulate downloading a large file (video, software, etc.)."""
        source_ip = f"192.168.1.{random.randint(10, 100)}"
        dest_ip = f"203.0.113.{random.randint(1, 254)}"
        
        file_types = ["video.mp4", "software.zip", "backup.tar.gz", "image.iso"]
        file_type = random.choice(file_types)
        
        self.logger.info(f"HTTP: Large download {file_type} from {source_ip} to {dest_ip}")
        
    def _simulate_file_transfer(self):
        """Simulate secure file transfer over SSH/SFTP."""
        source_ip = f"10.0.0.{random.randint(10, 100)}"
        dest_ip = f"10.0.0.{random.randint(1, 254)}"
        
        self.logger.info(f"SFTP: File transfer from {source_ip} to {dest_ip}:22")
    
    def _update_stack_statistics(self):
        """
        Update the TCP/IP stack statistics with simulated traffic.
        
        This makes the demo traffic appear in the stack's statistics
        and monitoring displays.
        """
        if not hasattr(self.stack, 'stats'):
            return
            
        # Add realistic increments to statistics
        packet_increment = random.randint(1, 4)
        byte_increment = random.randint(64, 1500)
        
        self.stack.stats["packets_sent"] += packet_increment
        self.stack.stats["packets_received"] += packet_increment
        self.stack.stats["bytes_sent"] += byte_increment 
        self.stack.stats["bytes_received"] += byte_increment
        
        # Occasionally simulate errors (network is not perfect!)
        if random.random() < self.error_probability:
            self.stack.stats["errors"] += 1
            error_types = [
                "Checksum mismatch",
                "Timeout waiting for ACK", 
                "Route not found",
                "Port unreachable",
                "Network unreachable"
            ]
            error_type = random.choice(error_types)
            self.logger.warning(f"Simulated network error: {error_type}")
    
    def generate_custom_traffic(self, traffic_type: str, count: int = 10):
        """
        Generate a specific type of traffic on demand.
        
        This allows for targeted demonstration of particular protocols
        or network scenarios.
        
        Args:
            traffic_type: Type of traffic to generate
            count: Number of packets to generate
        """
        self.logger.info(f"Generating {count} {traffic_type} packets")
        
        for i in range(count):
            if not self.running:
                break
                
            if traffic_type == "web":
                self._simulate_web_traffic(i)
            elif traffic_type == "ssh":
                self._simulate_ssh_traffic(i)
            elif traffic_type == "dns":
                self._simulate_dns_traffic(i)
            elif traffic_type == "icmp":
                self._simulate_icmp_traffic(i)
            elif traffic_type == "email":
                self._simulate_email_traffic(i)
            else:
                self.logger.warning(f"Unknown traffic type: {traffic_type}")
                return
                
            # Brief pause between generated packets
            time.sleep(random.uniform(0.1, 0.5))
    
    def get_statistics(self) -> dict:
        """
        Get statistics about the demo traffic generator.
        
        Returns:
            Dictionary with generator statistics
        """
        return {
            "running": self.running,
            "traffic_patterns": self.traffic_patterns,
            "error_probability": self.error_probability,
            "burst_probability": self.burst_probability,
            "traffic_interval": self.traffic_interval
        }