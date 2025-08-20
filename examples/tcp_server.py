#!/usr/bin/env python3
"""
TCP Server Example

This example demonstrates how to create a TCP server using our custom
TCP/IP stack implementation. The server can accept multiple client
connections and handle various types of requests.

This is like answering phone calls - you listen for incoming calls,
answer them, have conversations, then hang up when done.
"""

import sys
import time
import threading
import argparse
from pathlib import Path

# Add the parent directory to the path so we can import our TCP/IP stack
sys.path.insert(0, str(Path(__file__).parent.parent))

from tcp_ip_stack import TCPIPStack, create_logger

class SimpleTCPServer:
    """
    A simple TCP server using our custom TCP/IP stack.
    
    This demonstrates how to:
    - Listen for incoming connections
    - Accept client connections
    - Handle multiple clients simultaneously
    - Process different types of requests
    """
    
    def __init__(self, stack: TCPIPStack, port: int = 8080):
        """
        Initialize the TCP server.
        
        Args:
            stack: TCP/IP stack instance to use for networking
            port: Port number to listen on
        """
        self.stack = stack
        self.port = port
        self.logger = create_logger(f"TCPServer-{port}")
        self.running = False
        self.connections = {}  # Track active connections
        self.message_handlers = {}  # Custom message handlers
        
        # Set up default message handlers
        self._setup_default_handlers()
    
    def _setup_default_handlers(self):
        """Set up default handlers for common message types."""
        self.add_handler("ECHO", self._handle_echo)
        self.add_handler("TIME", self._handle_time)
        self.add_handler("HELP", self._handle_help)
        self.add_handler("STATUS", self._handle_status)
    
    def add_handler(self, command: str, handler_func):
        """
        Add a custom message handler.
        
        Args:
            command: Command string to handle
            handler_func: Function to call when command is received
        """
        self.message_handlers[command.upper()] = handler_func
        self.logger.debug(f"Added handler for command: {command}")
    
    def start(self):
        """
        Start the TCP server.
        
        This begins listening for incoming connections and processes
        them in the background.
        """
        if self.running:
            self.logger.warning("Server already running")
            return
        
        try:
            # Allocate port for listening
            listen_port = self.stack.transport_layer.allocate_port(self.port)
            if listen_port != self.port:
                self.logger.warning(f"Requested port {self.port} not available, using {listen_port}")
                self.port = listen_port
            
            self.running = True
            
            # Start listening thread
            listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
            listen_thread.start()
            
            self.logger.info(f"TCP server started on port {self.port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            raise
    
    def stop(self):
        """
        Stop the TCP server.
        
        This closes all active connections and stops accepting new ones.
        """
        if not self.running:
            return
        
        self.running = False
        
        # Close all active connections
        for connection_id, connection in list(self.connections.items()):
            self._close_connection(connection_id, connection)
        
        # Release the listening port
        self.stack.transport_layer.release_port(self.port)
        
        self.logger.info("TCP server stopped")
    
    def _listen_loop(self):
        """
        Main server loop that listens for incoming connections.
        
        This runs continuously while the server is active, simulating
        the process of listening for and accepting new client connections.
        """
        self.logger.info(f"Listening for connections on port {self.port}")
        
        while self.running:
            try:
                # Simulate checking for incoming connections
                # In a real implementation, this would use the transport layer
                # to check for SYN packets on our listening port
                
                # For demonstration, we'll simulate occasional incoming connections
                import random
                if random.random() < 0.1:  # 10% chance per iteration
                    self._simulate_incoming_connection()
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in listen loop: {e}")
                time.sleep(1)
    
    def _simulate_incoming_connection(self):
        """
        Simulate an incoming client connection.
        
        In a real implementation, this would be triggered by
        receiving a SYN packet from a client.
        """
        # Generate a simulated client
        client_ip = f"192.168.1.{random.randint(10, 200)}"
        client_port = random.randint(32768, 65535)
        
        # Create connection object
        connection = self.stack.transport_layer.create_tcp_connection(
            client_ip, client_port, self.port
        )
        
        # Generate unique connection ID
        connection_id = f"{client_ip}:{client_port}"
        
        # Simulate accepting the connection
        syn_packet = type('SYNPacket', (), {
            'sequence_number': random.randint(1000, 9999),
            'source_port': client_port,
            'dest_port': self.port
        })()
        
        synack_packet = connection.accept_connection(syn_packet)
        
        if synack_packet:
            self.connections[connection_id] = connection
            self.logger.info(f"Accepted connection from {connection_id}")
            
            # Start handling this connection in a separate thread
            client_thread = threading.Thread(
                target=self._handle_connection, 
                args=(connection_id, connection),
                daemon=True
            )
            client_thread.start()
    
    def _handle_connection(self, connection_id: str, connection):
        """
        Handle communication with a connected client.
        
        This processes incoming messages and sends appropriate responses.
        
        Args:
            connection_id: Unique identifier for this connection
            connection: TCP connection object
        """
        self.logger.info(f"Handling connection {connection_id}")
        
        try:
            # Send welcome message
            welcome_msg = f"Welcome to TCP Server on port {self.port}!\n"
            welcome_msg += "Available commands: ECHO, TIME, HELP, STATUS\n"
            welcome_msg += "Type HELP for more information.\n"
            
            self._send_response(connection, welcome_msg)
            
            # Main message processing loop
            while self.running and connection.state.value == "ESTABLISHED":
                # Simulate receiving messages from client
                message = self._simulate_receive_message(connection_id)
                
                if message:
                    self.logger.info(f"Received from {connection_id}: '{message}'")
                    
                    # Process the message
                    response = self._process_message(message, connection_id)
                    
                    if response:
                        self._send_response(connection, response)
                
                time.sleep(2)  # Check for messages every 2 seconds
                
        except Exception as e:
            self.logger.error(f"Error handling connection {connection_id}: {e}")
        finally:
            self._close_connection(connection_id, connection)
    
    def _simulate_receive_message(self, connection_id: str) -> str:
        """
        Simulate receiving a message from a client.
        
        In a real implementation, this would read from the connection's
        receive buffer populated by the transport layer.
        """
        import random
        
        # Simulate occasional messages from clients
        if random.random() < 0.3:  # 30% chance
            sample_messages = [
                "ECHO Hello Server!",
                "TIME",
                "STATUS", 
                "HELP",
                "ECHO Testing TCP connection",
                "PING",
                "QUIT"
            ]
            return random.choice(sample_messages)
        
        return None
    
    def _process_message(self, message: str, connection_id: str) -> str:
        """
        Process a message from a client and generate a response.
        
        Args:
            message: Message received from client
            connection_id: ID of the connection that sent the message
            
        Returns:
            Response message to send back
        """
        message = message.strip()
        
        # Handle QUIT command specially
        if message.upper() == "QUIT":
            return "Goodbye! Closing connection.\n"
        
        # Parse command and arguments
        parts = message.split(' ', 1)
        command = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        
        # Find and call appropriate handler
        if command in self.message_handlers:
            try:
                return self.message_handlers[command](args, connection_id)
            except Exception as e:
                self.logger.error(f"Handler error for {command}: {e}")
                return f"Error processing command '{command}': {e}\n"
        else:
            return f"Unknown command: '{command}'. Type HELP for available commands.\n"
    
    def _send_response(self, connection, response: str):
        """
        Send a response message to a client.
        
        Args:
            connection: TCP connection object
            response: Response message to send
        """
        try:
            # Convert response to bytes and send via TCP
            response_data = response.encode('utf-8')
            packet = self.stack.transport_layer.send_tcp_data(connection, response_data)
            
            self.logger.debug(f"Sent response: '{response.strip()}'")
            
        except Exception as e:
            self.logger.error(f"Failed to send response: {e}")
    
    def _close_connection(self, connection_id: str, connection):
        """
        Close a client connection gracefully.
        
        Args:
            connection_id: ID of connection to close
            connection: TCP connection object
        """
        try:
            if connection_id in self.connections:
                del self.connections[connection_id]
            
            # Initiate TCP close sequence
            fin_packet = self.stack.transport_layer.close_tcp_connection(connection)
            
            self.logger.info(f"Closed connection {connection_id}")
            
        except Exception as e:
            self.logger.error(f"Error closing connection {connection_id}: {e}")
    
    # Message Handler Functions
    
    def _handle_echo(self, args: str, connection_id: str) -> str:
        """Handle ECHO command - simply return the arguments."""
        if args:
            return f"ECHO: {args}\n"
        else:
            return "ECHO: (empty message)\n"
    
    def _handle_time(self, args: str, connection_id: str) -> str:
        """Handle TIME command - return current time."""
        current_time = time.strftime('%Y-%m-%d %H:%M:%S %Z')
        return f"Current server time: {current_time}\n"
    
    def _handle_help(self, args: str, connection_id: str) -> str:
        """Handle HELP command - return available commands."""
        help_text = "Available Commands:\n"
        help_text += "  ECHO <message>  - Echo back the message\n"
        help_text += "  TIME            - Get current server time\n"
        help_text += "  STATUS          - Get server status\n"
        help_text += "  HELP            - Show this help message\n"
        help_text += "  QUIT            - Close connection\n"
        return help_text
    
    def _handle_status(self, args: str, connection_id: str) -> str:
        """Handle STATUS command - return server statistics."""
        stats = self.stack.get_statistics()
        
        status_text = "Server Status:\n"
        status_text += f"  Active connections: {len(self.connections)}\n"
        status_text += f"  Server uptime: {stats['stack']['uptime_seconds']:.1f} seconds\n"
        status_text += f"  Packets sent: {stats['stack']['packets_sent']}\n"
        status_text += f"  Packets received: {stats['stack']['packets_received']}\n"
        status_text += f"  Errors: {stats['stack']['errors']}\n"
        
        return status_text
    
    def get_statistics(self) -> dict:
        """Get server statistics."""
        return {
            "running": self.running,
            "port": self.port,
            "active_connections": len(self.connections),
            "connection_ids": list(self.connections.keys()),
            "available_commands": list(self.message_handlers.keys())
        }

def demo_echo_server(stack: TCPIPStack, port: int):
    """
    Run a simple echo server demonstration.
    
    This creates a server that echoes back everything sent to it.
    """
    logger = create_logger("EchoServerDemo")
    logger.info(f"Starting Echo Server on port {port}")
    
    server = SimpleTCPServer(stack, port)
    
    try:
        server.start()
        
        print(f"\nEcho Server running on port {port}")
        print("Connect with: telnet localhost {port}")
        print("Or use the TCP client example")
        print("Press Ctrl+C to stop")
        
        # Keep server running
        while server.running:
            time.sleep(1)
            
            # Display periodic statistics
            stats = server.get_statistics()
            if len(stats["active_connections"]) > 0:
                logger.info(f"Active connections: {stats['active_connections']}")
    
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    finally:
        server.stop()

def demo_http_server(stack: TCPIPStack, port: int):
    """
    Run a simple HTTP server demonstration.
    
    This creates a basic web server using our TCP implementation.
    """
    logger = create_logger("HTTPServerDemo")
    logger.info(f"Starting HTTP Server on port {port}")
    
    # Create a custom HTTP server by adding HTTP-specific handlers
    server = SimpleTCPServer(stack, port)
    
    def handle_http_request(data: str, connection_id: str) -> str:
        """Handle HTTP requests."""
        lines = data.split('\n')
        if lines and lines[0].startswith('GET'):
            # Parse HTTP request
            request_line = lines[0]
            parts = request_line.split()
            
            if len(parts) >= 2:
                path = parts[1]
                
                # Generate HTTP response
                if path == '/':
                    content = "<html><body><h1>Welcome to TCP/IP Stack HTTP Server!</h1></body></html>"
                elif path == '/status':
                    stats = stack.get_statistics()
                    content = f"<html><body><h1>Server Status</h1><pre>{stats}</pre></body></html>"
                else:
                    content = "<html><body><h1>404 Not Found</h1></body></html>"
                
                response = "HTTP/1.1 200 OK\r\n"
                response += "Content-Type: text/html\r\n"
                response += f"Content-Length: {len(content)}\r\n"
                response += "Connection: close\r\n"
                response += "\r\n"
                response += content
                
                return response
        
        return "HTTP/1.1 400 Bad Request\r\n\r\nBad Request"
    
    # Add HTTP handler
    server.add_handler("GET", handle_http_request)
    
    try:
        server.start()
        
        print(f"\nHTTP Server running on port {port}")
        print(f"Open http://localhost:{port} in your browser")
        print("Press Ctrl+C to stop")
        
        while server.running:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    finally:
        server.stop()

def main():
    """Main entry point for the TCP server example."""
    parser = argparse.ArgumentParser(
        description="TCP Server Example using custom TCP/IP stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --port 8080                  # Start echo server on port 8080
  %(prog)s --port 8080 --type http      # Start HTTP server
  %(prog)s --port 7777 --type echo      # Start echo server  
        """
    )
    
    parser.add_argument("--port", type=int, default=8080,
                       help="Port number to listen on (default: 8080)")
    parser.add_argument("--type", choices=["echo", "http"], default="echo",
                       help="Server type (default: echo)")
    parser.add_argument("--interface", default="lo",
                       help="Network interface to use (default: lo)")
    
    args = parser.parse_args()
    
    # Create and start TCP/IP stack
    print("Initializing TCP/IP stack...")
    stack = TCPIPStack(args.interface)
    
    try:
        stack.start()
        print("TCP/IP stack started successfully")
        
        if args.type == "echo":
            demo_echo_server(stack, args.port)
        elif args.type == "http":
            demo_http_server(stack, args.port)
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stack.stop()
        print("TCP/IP stack stopped")

if __name__ == "__main__":
    main()