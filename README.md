# TCP/IP Stack Implementation

A comprehensive educational implementation of the TCP/IP protocol stack in Python, demonstrating deep networking knowledge through functional protocol layers.

## Features

- **Complete Protocol Stack**: Implementation of Physical, Data Link, Network, Transport, and Application layers
- **Real-time Web Interface**: Monitor network traffic, routing tables, and connection states
- **Demo Traffic Generator**: Simulates realistic HTTP, SSH, DNS, and ICMP traffic
- **Interactive Examples**: TCP/UDP clients/servers and packet sniffer tools
- **Educational Focus**: Clean, well-documented code perfect for learning networking concepts

## Quick Start

### Prerequisites
- Python 3.7 or higher
- Flask (automatically installed)

### Installation and Setup

1. **Clone the repository**:
   ```bash
   git clone <your-repository-url>
   cd tcp-ip-stack
   ```

2. **Install dependencies**:
   ```bash
   pip install flask netifaces
   ```

3. **Run the web interface**:
   ```bash
   python main.py --mode web --interface lo --log-level INFO
   ```

4. **Open your browser** and go to: `http://localhost:5000`

### What You'll See

The web interface provides:
- **Real-time Statistics**: Monitor packets, connections, and throughput
- **Network Tools**: Send ping, perform traceroute, view routing tables
- **Traffic Simulation**: Generate and observe realistic network traffic
- **Layer Analysis**: See how data flows through protocol layers

## Project Structure

```
tcp-ip-stack/
├── main.py                 # Main entry point
├── web_interface.py        # Flask web interface
├── config.json            # Configuration settings
├── tcp_ip_stack/          # Core protocol implementation
│   ├── physical_layer.py
│   ├── data_link_layer.py
│   ├── network_layer.py
│   ├── transport_layer.py
│   ├── application_layer.py
│   ├── routing.py
│   ├── demo_traffic.py
│   └── utils.py
└── examples/              # Example applications
    ├── tcp_server.py
    ├── tcp_client.py
    └── packet_sniffer.py
```

## Usage Examples

### Start the Web Interface
```bash
python main.py --mode web --interface lo --log-level INFO
```

### Run Example TCP Server
```bash
python examples/tcp_server.py
```

### Run Packet Sniffer
```bash
python examples/packet_sniffer.py
```

## Key Features Demonstrated

- **TCP Connection Management**: 3-way handshake, data transfer, connection termination
- **IP Routing**: Longest prefix matching, routing table management
- **Packet Processing**: Header parsing, checksum validation, fragmentation
- **Error Handling**: Timeout management, retransmission, error recovery
- **Real-time Monitoring**: Live statistics and network visualization

## Configuration

Edit `config.json` to modify:
- Server settings (host, port, debug mode)
- Protocol parameters (MTU, buffer sizes, timeouts)
- Simulation settings (error rates, delays)

## Learning Objectives

This implementation demonstrates:
- How network protocols work in practice
- Data flow through protocol layers
- Connection state management
- Routing and forwarding decisions
- Error detection and correction
- Performance monitoring and optimization

## Technical Details

- **Simulation Mode**: Uses loopback interface for safe operation
- **Thread-safe**: Concurrent packet processing and connection handling
- **Modular Design**: Clear separation between protocol layers
- **Comprehensive Logging**: Detailed debug information available
- **Standards Compliant**: Follows RFC specifications for TCP/IP protocols

## Contributing

This project is designed for educational purposes. Feel free to:
- Experiment with different configurations
- Add new protocol features
- Enhance the web interface
- Create additional examples

## License

Open source - feel free to use for learning and educational purposes.