"""
Application Layer Implementation

This is the layer closest to the user - it provides network services
that applications can use. Think of it as the "customer service desk"
of the network stack, providing easy-to-use services for programs.

Key concepts demonstrated:
- HTTP protocol implementation
- Client-server communication patterns
- Application protocol design
- Service discovery and registration
- Message formatting and parsing
"""

import json
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from urllib.parse import urlparse, parse_qs

class HTTPRequest:
    """
    HTTP Request - How Web Browsers Talk to Web Servers
    
    HTTP (HyperText Transfer Protocol) is the foundation of the web.
    Every time you visit a website, your browser sends an HTTP request.
    
    Request format:
    GET /index.html HTTP/1.1
    Host: www.example.com
    User-Agent: Mozilla/5.0...
    
    [blank line]
    [optional body data]
    """
    
    def __init__(self, method: str = "GET", path: str = "/", version: str = "HTTP/1.1"):
        """
        Create an HTTP request.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Resource path (like "/users/123" or "/api/data")
            version: HTTP protocol version
        """
        self.method = method.upper()
        self.path = path
        self.version = version
        self.headers = {}
        self.body = b''
        
        # Add default headers
        self.headers['Host'] = 'localhost'
        self.headers['User-Agent'] = 'TCP-IP-Stack/1.0'
        self.headers['Connection'] = 'keep-alive'
    
    def add_header(self, name: str, value: str):
        """Add a header to the request."""
        self.headers[name] = value
    
    def set_body(self, data: bytes):
        """Set the request body (for POST, PUT requests)."""
        self.body = data
        self.headers['Content-Length'] = str(len(data))
    
    def to_bytes(self) -> bytes:
        """Convert request to bytes for transmission over network."""
        # Build request line
        request_line = f"{self.method} {self.path} {self.version}\r\n"
        
        # Build headers
        header_lines = ""
        for name, value in self.headers.items():
            header_lines += f"{name}: {value}\r\n"
        
        # Combine request line, headers, blank line, and body
        request_str = request_line + header_lines + "\r\n"
        return request_str.encode('utf-8') + self.body
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['HTTPRequest']:
        """Parse HTTP request from received bytes."""
        try:
            # Split headers from body
            if b'\r\n\r\n' in data:
                header_part, body_part = data.split(b'\r\n\r\n', 1)
            else:
                header_part = data
                body_part = b''
            
            header_lines = header_part.decode('utf-8').split('\r\n')
            
            # Parse request line
            request_line = header_lines[0]
            parts = request_line.split(' ')
            if len(parts) != 3:
                return None
            
            method, path, version = parts
            request = cls(method, path, version)
            
            # Parse headers
            for line in header_lines[1:]:
                if ':' in line:
                    name, value = line.split(':', 1)
                    request.headers[name.strip()] = value.strip()
            
            request.body = body_part
            return request
            
        except Exception:
            return None
    
    def __str__(self) -> str:
        """Human-readable representation of this request."""
        return f"HTTP {self.method} {self.path}"

class HTTPResponse:
    """
    HTTP Response - How Web Servers Reply to Browsers
    
    After a web server processes your request, it sends back a response
    with a status code, headers, and the requested content.
    
    Response format:
    HTTP/1.1 200 OK
    Content-Type: text/html
    Content-Length: 1234
    
    [blank line]
    <html>...</html>
    """
    
    def __init__(self, status_code: int = 200, reason: str = "OK", version: str = "HTTP/1.1"):
        """
        Create an HTTP response.
        
        Args:
            status_code: HTTP status (200=OK, 404=Not Found, 500=Error, etc.)
            reason: Human-readable status description
            version: HTTP protocol version
        """
        self.version = version
        self.status_code = status_code
        self.reason = reason
        self.headers = {}
        self.body = b''
        
        # Add default headers
        self.headers['Server'] = 'TCP-IP-Stack/1.0'
        self.headers['Connection'] = 'keep-alive'
        self.headers['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
    
    def add_header(self, name: str, value: str):
        """Add a header to the response."""
        self.headers[name] = value
    
    def set_body(self, data: bytes, content_type: str = "text/html"):
        """Set the response body."""
        self.body = data
        self.headers['Content-Length'] = str(len(data))
        self.headers['Content-Type'] = content_type
    
    def set_json_body(self, data: dict):
        """Set the response body as JSON."""
        json_data = json.dumps(data).encode('utf-8')
        self.set_body(json_data, "application/json")
    
    def to_bytes(self) -> bytes:
        """Convert response to bytes for transmission."""
        # Build status line
        status_line = f"{self.version} {self.status_code} {self.reason}\r\n"
        
        # Build headers
        header_lines = ""
        for name, value in self.headers.items():
            header_lines += f"{name}: {value}\r\n"
        
        # Combine status line, headers, blank line, and body
        response_str = status_line + header_lines + "\r\n"
        return response_str.encode('utf-8') + self.body
    
    def __str__(self) -> str:
        """Human-readable representation of this response."""
        return f"HTTP {self.status_code} {self.reason}"

class SimpleHTTPServer:
    """
    Simple HTTP Web Server
    
    This demonstrates how web servers work - they listen for HTTP requests
    and send back appropriate responses. Like a restaurant that takes
    orders (requests) and serves food (responses).
    """
    
    def __init__(self, port: int = 8080):
        """
        Initialize the HTTP server.
        
        Args:
            port: Port number to listen on (like 80 for regular websites)
        """
        self.port = port
        self.logger = logging.getLogger(f"HTTPServer-{port}")
        self.routes = {}  # URL patterns and their handler functions
        self.running = False
        
        # Built-in routes for demonstration
        self.add_route("GET", "/", self._handle_root)
        self.add_route("GET", "/status", self._handle_status)
        self.add_route("GET", "/api/info", self._handle_api_info)
        
    def add_route(self, method: str, path: str, handler: Callable):
        """
        Register a handler function for a specific URL pattern.
        
        This is like training a waiter - "when someone asks for the menu,
        bring them this specific menu."
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path (like "/users" or "/api/data")
            handler: Function to call when this route is requested
        """
        route_key = f"{method.upper()} {path}"
        self.routes[route_key] = handler
        self.logger.debug(f"Added route: {route_key}")
    
    def handle_request(self, request: HTTPRequest) -> HTTPResponse:
        """
        Process an incoming HTTP request and generate a response.
        
        This is the main logic of a web server - look at what the client
        wants and figure out how to respond.
        
        Args:
            request: The HTTP request from a client
            
        Returns:
            HTTP response to send back
        """
        route_key = f"{request.method} {request.path}"
        
        # Check if we have a handler for this route
        if route_key in self.routes:
            try:
                handler = self.routes[route_key]
                response = handler(request)
                self.logger.info(f"Handled {route_key} -> {response.status_code}")
                return response
                
            except Exception as e:
                self.logger.error(f"Error handling {route_key}: {e}")
                return self._create_error_response(500, "Internal Server Error")
        
        else:
            # Route not found
            self.logger.warning(f"No handler for {route_key}")
            return self._create_error_response(404, "Not Found")
    
    def _handle_root(self, request: HTTPRequest) -> HTTPResponse:
        """Handle requests to the root URL (/)."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>TCP/IP Stack Demo Server</title>
        </head>
        <body>
            <h1>Welcome to the TCP/IP Stack Demo!</h1>
            <p>This is a simple HTTP server running on our custom TCP/IP implementation.</p>
            <ul>
                <li><a href="/status">Server Status</a></li>
                <li><a href="/api/info">API Information</a></li>
            </ul>
        </body>
        </html>
        """
        
        response = HTTPResponse(200, "OK")
        response.set_body(html_content.encode('utf-8'), "text/html")
        return response
    
    def _handle_status(self, request: HTTPRequest) -> HTTPResponse:
        """Handle requests to /status."""
        status_info = {
            "server": "TCP/IP Stack Demo",
            "status": "running",
            "port": self.port,
            "time": time.strftime('%Y-%m-%d %H:%M:%S'),
            "routes": list(self.routes.keys())
        }
        
        response = HTTPResponse(200, "OK")
        response.set_json_body(status_info)
        return response
    
    def _handle_api_info(self, request: HTTPRequest) -> HTTPResponse:
        """Handle requests to /api/info."""
        api_info = {
            "name": "TCP/IP Stack Demo API",
            "version": "1.0",
            "description": "Educational implementation of network protocols",
            "endpoints": [
                {"method": "GET", "path": "/", "description": "Home page"},
                {"method": "GET", "path": "/status", "description": "Server status"},
                {"method": "GET", "path": "/api/info", "description": "API information"}
            ]
        }
        
        response = HTTPResponse(200, "OK")
        response.set_json_body(api_info)
        return response
    
    def _create_error_response(self, status_code: int, reason: str) -> HTTPResponse:
        """Create a standard error response."""
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{status_code} {reason}</title>
        </head>
        <body>
            <h1>{status_code} {reason}</h1>
            <p>The requested resource could not be found or processed.</p>
        </body>
        </html>
        """
        
        response = HTTPResponse(status_code, reason)
        response.set_body(error_html.encode('utf-8'), "text/html")
        return response

class ApplicationLayer:
    """
    Application Layer - User-Facing Network Services
    
    This layer provides high-level network services that applications
    can easily use. It's like a translator that converts between
    human-friendly requests and network-friendly packets.
    
    Services provided:
    - HTTP web server and client functionality
    - Custom application protocols
    - Service discovery and registration
    - Message encoding/decoding
    - Session management
    """
    
    def __init__(self):
        """Initialize the application layer."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Service registry - like a phone book for network services
        self.services = {}
        
        # Active HTTP servers
        self.http_servers = {}
        
        # Application statistics
        self.stats = {
            "http_requests_handled": 0,
            "http_responses_sent": 0,
            "custom_messages_processed": 0,
            "services_registered": 0,
            "active_sessions": 0
        }
        
        self.logger.info("Application layer initialized")
    
    def register_service(self, name: str, port: int, protocol: str = "HTTP", 
                        description: str = ""):
        """
        Register a network service for discovery.
        
        This is like listing your business in the phone book so others can find it.
        
        Args:
            name: Human-readable service name
            port: Port number the service listens on
            protocol: Protocol used (HTTP, FTP, SSH, etc.)
            description: What this service does
        """
        self.services[name] = {
            "port": port,
            "protocol": protocol,
            "description": description,
            "registered_at": time.time()
        }
        
        self.stats["services_registered"] += 1
        self.logger.info(f"Registered service: {name} on port {port} ({protocol})")
    
    def start_http_server(self, port: int = 8080) -> SimpleHTTPServer:
        """
        Start an HTTP web server.
        
        This creates a web server that can respond to browser requests.
        
        Args:
            port: Port number to listen on
            
        Returns:
            HTTP server instance
        """
        if port in self.http_servers:
            raise Exception(f"HTTP server already running on port {port}")
        
        server = SimpleHTTPServer(port)
        self.http_servers[port] = server
        
        # Register the service
        self.register_service(f"HTTP-{port}", port, "HTTP", "Web server")
        
        self.logger.info(f"Started HTTP server on port {port}")
        return server
    
    def process_http_request(self, request_data: bytes, server_port: int) -> bytes:
        """
        Process an incoming HTTP request.
        
        This is called when HTTP data arrives from the transport layer.
        
        Args:
            request_data: Raw HTTP request bytes
            server_port: Which server this request is for
            
        Returns:
            HTTP response bytes to send back
        """
        # Parse the HTTP request
        request = HTTPRequest.from_bytes(request_data)
        
        if not request:
            # Malformed request
            error_response = HTTPResponse(400, "Bad Request")
            error_response.set_body(b"Invalid HTTP request", "text/plain")
            return error_response.to_bytes()
        
        # Find the appropriate server
        server = self.http_servers.get(server_port)
        if not server:
            error_response = HTTPResponse(503, "Service Unavailable")
            error_response.set_body(b"No server available", "text/plain")
            return error_response.to_bytes()
        
        # Handle the request
        response = server.handle_request(request)
        
        # Update statistics
        self.stats["http_requests_handled"] += 1
        self.stats["http_responses_sent"] += 1
        
        return response.to_bytes()
    
    def create_http_request(self, method: str, url: str, data: bytes = b'') -> bytes:
        """
        Create an HTTP request for sending to a server.
        
        This is used when our stack acts as an HTTP client.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            data: Request body data
            
        Returns:
            HTTP request bytes ready for transmission
        """
        # Parse the URL
        parsed = urlparse(url)
        
        # Create the request
        request = HTTPRequest(method, parsed.path or "/")
        request.add_header("Host", parsed.hostname or "localhost")
        
        if data:
            request.set_body(data)
        
        self.logger.debug(f"Created HTTP request: {method} {url}")
        return request.to_bytes()
    
    def process_custom_message(self, message_data: bytes, protocol: str) -> Optional[bytes]:
        """
        Process a custom application protocol message.
        
        This demonstrates how to implement custom protocols beyond HTTP.
        For example, a chat protocol, file transfer protocol, or game protocol.
        
        Args:
            message_data: Raw message bytes
            protocol: Which custom protocol this is for
            
        Returns:
            Response bytes, or None if no response needed
        """
        try:
            if protocol == "ECHO":
                # Simple echo protocol - just send back what we received
                response = b"ECHO: " + message_data
                self.logger.debug(f"Processed ECHO message: {len(message_data)} bytes")
                
            elif protocol == "TIME":
                # Time protocol - send current time
                current_time = time.strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')
                response = b"TIME: " + current_time
                self.logger.debug("Processed TIME request")
                
            elif protocol == "CHAT":
                # Simple chat protocol
                message = message_data.decode('utf-8', errors='ignore')
                response = f"CHAT: Received message: {message}".encode('utf-8')
                self.logger.debug(f"Processed CHAT message: {message}")
                
            else:
                # Unknown protocol
                response = b"ERROR: Unknown protocol"
                self.logger.warning(f"Unknown protocol: {protocol}")
            
            self.stats["custom_messages_processed"] += 1
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing custom message: {e}")
            return b"ERROR: Processing failed"
    
    def discover_services(self) -> Dict[str, Any]:
        """
        Get a list of all registered services.
        
        This is like looking up services in a phone book.
        
        Returns:
            Dictionary of available services
        """
        return self.services.copy()
    
    def send_notification(self, message: str, recipients: List[str] = None):
        """
        Send a notification message to connected clients.
        
        This demonstrates how applications can broadcast messages.
        
        Args:
            message: Notification message
            recipients: List of recipients (or None for broadcast)
        """
        notification = {
            "type": "notification",
            "message": message,
            "timestamp": time.time(),
            "recipients": recipients or ["all"]
        }
        
        self.logger.info(f"Sending notification: {message}")
        # In a real implementation, this would send the notification
        # through the transport layer to connected clients
    
    def get_statistics(self) -> dict:
        """Get current application layer statistics."""
        return {
            **self.stats,
            "registered_services": len(self.services),
            "active_http_servers": len(self.http_servers),
            "available_services": list(self.services.keys())
        }
    
    def shutdown_service(self, name: str):
        """
        Shut down a registered service.
        
        This removes the service from the registry and stops any
        associated servers.
        """
        if name in self.services:
            service_info = self.services[name]
            port = service_info["port"]
            
            # Stop HTTP server if it exists
            if port in self.http_servers:
                del self.http_servers[port]
                self.logger.info(f"Stopped HTTP server on port {port}")
            
            # Remove from service registry
            del self.services[name]
            self.logger.info(f"Unregistered service: {name}")
        
        else:
            self.logger.warning(f"Service not found: {name}")
    
    def get_service_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific service.
        
        Args:
            name: Service name
            
        Returns:
            Service information dictionary, or None if not found
        """
        return self.services.get(name)