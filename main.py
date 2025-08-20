#!/usr/bin/env python3
"""
TCP/IP Stack Implementation - Main Application

This is the main entry point for the TCP/IP stack demonstration.
It provides multiple ways to run and test the networking implementation:

1. Web Interface Mode: Interactive dashboard for monitoring and testing
2. Demo Mode: Automated demonstration of all networking features  
3. CLI Mode: Command-line tools for network testing
4. Server Mode: Run as a network service

Usage Examples:
    python main.py --mode web                    # Start web interface
    python main.py --mode demo                   # Run automated demo
    python main.py --mode cli --ping 8.8.8.8   # Ping test
    python main.py --mode server --port 8080    # Start HTTP server
"""

import argparse
import logging
import sys
import time
import signal
from typing import Optional

# Import our TCP/IP stack components
from tcp_ip_stack import TCPIPStack, create_logger
from web_interface import WebInterface

def setup_logging(level: str = "INFO"):
    """
    Configure logging for the entire application.
    
    This sets up consistent logging across all components so we can
    see what's happening inside the network stack.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Reduce noise from external libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

def signal_handler(signum, frame, stack: Optional[TCPIPStack] = None):
    """
    Handle shutdown signals gracefully.
    
    This ensures the network stack is properly shut down when
    the user presses Ctrl+C or the system sends a termination signal.
    """
    print("\nReceived shutdown signal. Stopping TCP/IP stack...")
    
    if stack and stack.is_running():
        stack.stop()
    
    print("TCP/IP stack stopped. Goodbye!")
    sys.exit(0)

def run_web_interface(args):
    """
    Run the web interface for interactive demonstration.
    
    This starts both the TCP/IP stack and a web server that provides
    a user-friendly dashboard for monitoring and testing the network stack.
    
    Args:
        args: Command line arguments
    """
    logger = create_logger("WebMode")
    logger.info("Starting TCP/IP Stack in Web Interface Mode")
    
    try:
        # Create and start the web interface
        web_interface = WebInterface(
            host=args.host,
            port=args.port,
            debug=args.debug,
            interface=args.interface
        )
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, web_interface.stack))
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, web_interface.stack))
        
        logger.info(f"Web interface starting on http://{args.host}:{args.port}")
        logger.info("Press Ctrl+C to stop")
        
        # Start the web interface (this blocks until shutdown)
        web_interface.run()
        
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}")
        sys.exit(1)

def run_demo_mode(args):
    """
    Run automated demonstration of all networking features.
    
    This showcases the TCP/IP stack capabilities without requiring
    user interaction - perfect for presentations or testing.
    
    Args:
        args: Command line arguments
    """
    logger = create_logger("DemoMode")
    logger.info("Starting TCP/IP Stack in Demo Mode")
    
    try:
        # Create and start the stack
        stack = TCPIPStack(args.interface)
        
        # Set up signal handler
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, stack))
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, stack))
        
        logger.info("Initializing TCP/IP stack...")
        stack.start()
        
        logger.info("TCP/IP stack started successfully!")
        logger.info("Running networking demonstrations...")
        
        # Demonstration sequence
        demonstrate_ping(stack, logger)
        demonstrate_routing(stack, logger)
        demonstrate_statistics(stack, logger)
        
        logger.info("Demo complete! Stack will continue running...")
        logger.info("Press Ctrl+C to stop")
        
        # Keep running until interrupted
        while stack.is_running():
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        sys.exit(1)
    finally:
        if 'stack' in locals():
            stack.stop()

def demonstrate_ping(stack: TCPIPStack, logger):
    """Demonstrate ping functionality."""
    logger.info("\n--- Ping Demonstration ---")
    
    # Test ping to localhost
    logger.info("Testing connectivity to localhost...")
    ping_result = stack.ping("127.0.0.1", count=3)
    
    logger.info(f"Ping Results:")
    logger.info(f"  Packets sent: {ping_result['packets_sent']}")
    logger.info(f"  Packets received: {ping_result['packets_received']}")
    logger.info(f"  Packet loss: {ping_result['packet_loss']:.1f}%")
    
    if ping_result['packets_received'] > 0:
        logger.info(f"  Average time: {ping_result['avg_time']:.1f}ms")

def demonstrate_routing(stack: TCPIPStack, logger):
    """Demonstrate routing functionality."""
    logger.info("\n--- Routing Demonstration ---")
    
    # Show current routing table
    routes = stack.routing_table.get_routing_table()
    logger.info(f"Current routing table ({len(routes)} routes):")
    
    for route in routes:
        logger.info(f"  {route['destination']} via {route['gateway']} dev {route['interface']}")
    
    # Add a test route
    logger.info("Adding test route...")
    stack.routing_table.add_route("192.168.100.0/24", "192.168.1.1", "eth0")
    
    # Test route lookup
    test_route = stack.routing_table.get_route("192.168.100.50")
    if test_route:
        logger.info(f"Route for 192.168.100.50: {test_route}")

def demonstrate_statistics(stack: TCPIPStack, logger):
    """Demonstrate statistics collection."""
    logger.info("\n--- Statistics Demonstration ---")
    
    stats = stack.get_statistics()
    
    logger.info("Stack Statistics:")
    logger.info(f"  Running: {stats['stack']['running']}")
    logger.info(f"  Interface: {stats['stack']['interface']}")
    logger.info(f"  Packets sent: {stats['stack']['packets_sent']}")
    logger.info(f"  Packets received: {stats['stack']['packets_received']}")
    logger.info(f"  Errors: {stats['stack']['errors']}")
    
    logger.info("Layer Statistics:")
    for layer_name, layer_stats in stats.items():
        if layer_name != "stack":
            logger.info(f"  {layer_name.title()}: {layer_stats}")

def run_cli_mode(args):
    """
    Run command-line tools for network testing.
    
    This provides a command-line interface for performing
    specific networking tasks like ping tests or route management.
    
    Args:
        args: Command line arguments
    """
    logger = create_logger("CLIMode")
    logger.info("Starting TCP/IP Stack in CLI Mode")
    
    try:
        # Create and start the stack
        stack = TCPIPStack(args.interface)
        stack.start()
        
        if args.ping:
            # Perform ping test
            logger.info(f"Pinging {args.ping}...")
            result = stack.ping(args.ping, count=args.count, timeout=args.timeout)
            
            print(f"\nPing Results for {args.ping}:")
            print(f"Packets: {result['packets_sent']} sent, {result['packets_received']} received")
            print(f"Packet loss: {result['packet_loss']:.1f}%")
            
            if result['packets_received'] > 0:
                print(f"Times: min={result['min_time']:.1f}ms avg={result['avg_time']:.1f}ms max={result['max_time']:.1f}ms")
        
        elif args.routes:
            # Show routing table
            routes = stack.routing_table.get_routing_table()
            print(f"\nRouting Table ({len(routes)} routes):")
            print("Destination          Gateway              Interface    Metric")
            print("-" * 65)
            
            for route in routes:
                print(f"{route['destination']:<20} {route['gateway']:<20} {route['interface']:<12} {route['metric']}")
        
        elif args.stats:
            # Show statistics
            stats = stack.get_statistics()
            print("\nTCP/IP Stack Statistics:")
            print("=" * 50)
            
            for layer_name, layer_stats in stats.items():
                print(f"\n{layer_name.title()} Layer:")
                for key, value in layer_stats.items():
                    print(f"  {key}: {value}")
        
        else:
            print("No CLI action specified. Use --help for options.")
        
    except Exception as e:
        logger.error(f"CLI operation failed: {e}")
        sys.exit(1)
    finally:
        if 'stack' in locals():
            stack.stop()

def run_server_mode(args):
    """
    Run as a network server.
    
    This starts the TCP/IP stack as a server that can accept
    incoming connections and serve content.
    
    Args:
        args: Command line arguments
    """
    logger = create_logger("ServerMode")
    logger.info("Starting TCP/IP Stack in Server Mode")
    
    try:
        # Create and start the stack
        stack = TCPIPStack(args.interface)
        
        # Set up signal handler
        signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, stack))
        signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, stack))
        
        stack.start()
        
        # Start HTTP server
        http_server = stack.application_layer.start_http_server(args.port)
        
        logger.info(f"HTTP server listening on port {args.port}")
        logger.info("Press Ctrl+C to stop")
        
        # Keep running until interrupted
        while stack.is_running():
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server failed: {e}")
        sys.exit(1)
    finally:
        if 'stack' in locals():
            stack.stop()

def main():
    """
    Main application entry point.
    
    This parses command line arguments and dispatches to the
    appropriate mode (web, demo, cli, or server).
    """
    parser = argparse.ArgumentParser(
        description="TCP/IP Stack Implementation - Educational Networking Demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode web                          # Start interactive web interface
  %(prog)s --mode demo                         # Run automated demonstration
  %(prog)s --mode cli --ping 127.0.0.1       # Ping test via CLI
  %(prog)s --mode cli --routes                # Show routing table
  %(prog)s --mode server --port 8080          # Start HTTP server
  %(prog)s --interface eth0 --log-level DEBUG # Use specific interface with debug logging
        """
    )
    
    # Global options
    parser.add_argument("--mode", choices=["web", "demo", "cli", "server"], 
                       default="web", help="Operation mode (default: web)")
    parser.add_argument("--interface", default="lo", 
                       help="Network interface to use (default: lo)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       default="INFO", help="Logging level (default: INFO)")
    
    # Web interface options
    parser.add_argument("--host", default="0.0.0.0",
                       help="Web interface host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000,
                       help="Port number (default: 5000)")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug mode")
    
    # CLI options
    parser.add_argument("--ping", help="Ping destination IP address")
    parser.add_argument("--count", type=int, default=4,
                       help="Number of ping packets (default: 4)")
    parser.add_argument("--timeout", type=float, default=1.0,
                       help="Ping timeout in seconds (default: 1.0)")
    parser.add_argument("--routes", action="store_true",
                       help="Show routing table")
    parser.add_argument("--stats", action="store_true",
                       help="Show stack statistics")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Create main logger
    logger = create_logger("Main")
    logger.info("Starting TCP/IP Stack Implementation")
    logger.info(f"Mode: {args.mode}, Interface: {args.interface}")
    
    # Dispatch to appropriate mode
    try:
        if args.mode == "web":
            run_web_interface(args)
        elif args.mode == "demo":
            run_demo_mode(args)
        elif args.mode == "cli":
            run_cli_mode(args)
        elif args.mode == "server":
            run_server_mode(args)
        else:
            logger.error(f"Unknown mode: {args.mode}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()