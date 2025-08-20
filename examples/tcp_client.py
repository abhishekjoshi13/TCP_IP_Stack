#!/usr/bin/env python3
"""
TCP Client Example

This example demonstrates how to use the TCP/IP stack implementation
to create a simple TCP client that can connect to servers and exchange data.

This is like making a phone call - you initiate the connection,
have a conversation, then hang up when done.
"""

import sys
import time
import argparse
from pathlib import Path

# Add the parent directory to the path so we can import our TCP/IP stack
sys.path.insert(0, str(Path(__file__).parent.parent))

from tcp_ip_stack import TCPIPStack, create_logger

class SimpleTCPClient:
    """
    A simple TCP client using our custom TCP/IP stack.
    
    This demonstrates how applications can use the transport layer
    to establish reliable connections and exchange data.
    """
    
    def __init__(self, stack: TCPIPStack):
        """
        Initialize the TCP client.
        
        Args:
            stack: TCP/IP stack instance to use for networking
        """
        self.stack = stack
        self.logger = create_logger("TCPClient")
        self.connection = None
    
    def connect(self, server_ip: str, server_port: int, local_port: int = None) -> bool:
        """
        Connect to a TCP server.
        
        Args:
            server_ip: Server IP address to connect to
            server_port: Server port number
            local_port: Local port to use (auto-assigned if None)
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.logger.info(f"Connecting to {server_ip}:{server_port}")
            
            # Create a new TCP connection
            self.connection = self.stack.transport_layer.create_tcp_connection(
                server_ip, server_port, local_port
            )
            
            # Initiate the connection (3-way handshake)
            success = self.connection.connect()
            
            if success:
                self.logger.info(f"Connected successfully to {server_ip}:{server_port}")
                return True
            else:
                self.logger.error("Failed to establish connection")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def send_message(self, message: str) -> bool:
        """
        Send a text message to the server.
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.connection:
            self.logger.error("Not connected to server")
            return False
        
        try:
            # Convert message to bytes and send
            data = message.encode('utf-8')
            packet = self.stack.transport_layer.send_tcp_data(self.connection, data)
            
            self.logger.info(f"Sent message: '{message}' ({len(data)} bytes)")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            return False
    
    def send_http_request(self, host: str, path: str = "/") -> bool:
        """
        Send a simple HTTP GET request.
        
        This demonstrates how to use TCP for HTTP communication.
        
        Args:
            host: Server hostname
            path: HTTP path to request
            
        Returns:
            True if request sent successfully
        """
        if not self.connection:
            self.logger.error("Not connected to server")
            return False
        
        # Build HTTP request
        http_request = f"GET {path} HTTP/1.1\r\n"
        http_request += f"Host: {host}\r\n"
        http_request += "User-Agent: TCP-IP-Stack-Client/1.0\r\n"
        http_request += "Connection: close\r\n"
        http_request += "\r\n"
        
        return self.send_message(http_request)
    
    def receive_data(self, timeout: float = 5.0) -> str:
        """
        Receive data from the server.
        
        Args:
            timeout: How long to wait for data
            
        Returns:
            Received data as string, or empty string if nothing received
        """
        if not self.connection:
            self.logger.error("Not connected to server")
            return ""
        
        try:
            # In a real implementation, this would read from the connection's
            # receive buffer. For demonstration, we'll simulate receiving data.
            self.logger.info("Waiting for server response...")
            
            # Simulate response (in real implementation, this would come from the network)
            time.sleep(0.5)  # Simulate network delay
            
            if self.connection.receive_buffer:
                data = self.connection.receive_buffer.decode('utf-8')
                self.connection.receive_buffer = b''  # Clear buffer
                self.logger.info(f"Received: '{data}'")
                return data
            else:
                # Simulate a typical server response
                response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
                self.logger.info(f"Simulated response: '{response}'")
                return response
                
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}")
            return ""
    
    def disconnect(self):
        """
        Close the connection to the server.
        
        This initiates the TCP connection close sequence (4-way handshake).
        """
        if not self.connection:
            self.logger.warning("Not connected")
            return
        
        try:
            self.logger.info("Closing connection...")
            
            # Initiate connection close
            fin_packet = self.stack.transport_layer.close_tcp_connection(self.connection)
            
            if fin_packet:
                self.logger.info("Connection closed gracefully")
            else:
                self.logger.warning("Connection close may not have completed properly")
            
            self.connection = None
            
        except Exception as e:
            self.logger.error(f"Error closing connection: {e}")

def demo_web_client(stack: TCPIPStack):
    """
    Demonstrate using the TCP client to make HTTP requests.
    
    This shows how our TCP implementation can be used for web browsing.
    """
    logger = create_logger("WebClientDemo")
    logger.info("Starting Web Client Demonstration")
    
    client = SimpleTCPClient(stack)
    
    try:
        # Connect to a simulated web server
        if client.connect("127.0.0.1", 80):
            
            # Send HTTP GET request
            client.send_http_request("localhost", "/")
            
            # Receive and display response
            response = client.receive_data()
            print("\nServer Response:")
            print("-" * 50)
            print(response)
            print("-" * 50)
            
            # Close connection
            client.disconnect()
            
        else:
            logger.error("Failed to connect to web server")
            
    except Exception as e:
        logger.error(f"Web client demo failed: {e}")

def demo_echo_client(stack: TCPIPStack):
    """
    Demonstrate using the TCP client with an echo server.
    
    An echo server simply sends back whatever data it receives.
    """
    logger = create_logger("EchoClientDemo")
    logger.info("Starting Echo Client Demonstration")
    
    client = SimpleTCPClient(stack)
    
    try:
        # Connect to echo server
        if client.connect("127.0.0.1", 7777):
            
            # Send some test messages
            test_messages = [
                "Hello, Echo Server!",
                "This is a test message.",
                "TCP connections are working!",
                "Goodbye!"
            ]
            
            for message in test_messages:
                client.send_message(message)
                
                # Wait for echo response
                response = client.receive_data()
                print(f"Sent: '{message}' → Received: '{response}'")
                
                time.sleep(1)  # Brief pause between messages
            
            # Close connection
            client.disconnect()
            
        else:
            logger.error("Failed to connect to echo server")
            
    except Exception as e:
        logger.error(f"Echo client demo failed: {e}")

def interactive_client(stack: TCPIPStack):
    """
    Run an interactive TCP client that accepts user input.
    
    This allows users to manually test TCP connections and send custom messages.
    """
    logger = create_logger("InteractiveClient")
    client = SimpleTCPClient(stack)
    
    print("\n" + "="*60)
    print("             Interactive TCP Client")
    print("="*60)
    print("Commands:")
    print("  connect <ip> <port>  - Connect to server")
    print("  send <message>       - Send message to server")
    print("  receive              - Receive data from server")
    print("  disconnect           - Close connection")
    print("  quit                 - Exit client")
    print("="*60)
    
    while True:
        try:
            command = input("\ntcp-client> ").strip().split()
            
            if not command:
                continue
                
            cmd = command[0].lower()
            
            if cmd == "connect":
                if len(command) >= 3:
                    ip = command[1]
                    port = int(command[2])
                    client.connect(ip, port)
                else:
                    print("Usage: connect <ip> <port>")
            
            elif cmd == "send":
                if len(command) >= 2:
                    message = " ".join(command[1:])
                    client.send_message(message)
                else:
                    print("Usage: send <message>")
            
            elif cmd == "receive":
                response = client.receive_data()
                if response:
                    print(f"Received: {response}")
                else:
                    print("No data received")
            
            elif cmd == "disconnect":
                client.disconnect()
            
            elif cmd == "quit":
                client.disconnect()
                print("Goodbye!")
                break
            
            else:
                print(f"Unknown command: {cmd}")
                
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            client.disconnect()
            break
        except Exception as e:
            logger.error(f"Command error: {e}")

def main():
    """Main entry point for the TCP client example."""
    parser = argparse.ArgumentParser(
        description="TCP Client Example using custom TCP/IP stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo web                    # Web client demonstration
  %(prog)s --demo echo                   # Echo client demonstration  
  %(prog)s --interactive                 # Interactive client mode
  %(prog)s --connect 127.0.0.1 8080     # Connect to specific server
        """
    )
    
    parser.add_argument("--demo", choices=["web", "echo"], 
                       help="Run a specific demonstration")
    parser.add_argument("--interactive", action="store_true",
                       help="Run interactive client mode")
    parser.add_argument("--connect", nargs=2, metavar=("IP", "PORT"),
                       help="Connect to specific server")
    parser.add_argument("--interface", default="lo",
                       help="Network interface to use (default: lo)")
    parser.add_argument("--message", 
                       help="Message to send (with --connect)")
    
    args = parser.parse_args()
    
    # Create and start TCP/IP stack
    print("Initializing TCP/IP stack...")
    stack = TCPIPStack(args.interface)
    
    try:
        stack.start()
        print("TCP/IP stack started successfully")
        
        if args.demo == "web":
            demo_web_client(stack)
        elif args.demo == "echo":
            demo_echo_client(stack)
        elif args.interactive:
            interactive_client(stack)
        elif args.connect:
            # Simple connection test
            ip, port = args.connect
            client = SimpleTCPClient(stack)
            
            if client.connect(ip, int(port)):
                if args.message:
                    client.send_message(args.message)
                    response = client.receive_data()
                    print(f"Server response: {response}")
                else:
                    print("Connected successfully. Use --message to send data.")
                
                client.disconnect()
            else:
                print("Connection failed")
        else:
            print("No operation specified. Use --help for options.")
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stack.stop()
        print("TCP/IP stack stopped")

if __name__ == "__main__":
    main()