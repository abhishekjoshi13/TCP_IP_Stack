# TCP/IP Stack Testing Guide

This guide explains how to test and validate all features of the TCP/IP stack implementation. It provides comprehensive testing scenarios for each protocol layer and practical examples for demonstration.

## Quick Start Testing

### 1. Basic Functionality Test

```bash
# Start the web interface
python main.py --mode web

# Open browser to http://localhost:5000
# Click "Start Stack" button
# Verify statistics are updating
```

### 2. Command Line Testing

```bash
# Test ping functionality
python main.py --mode cli --ping 127.0.0.1 --count 5

# Show routing table
python main.py --mode cli --routes

# Display stack statistics
python main.py --mode cli --stats
```

### 3. Demo Mode

```bash
# Run automated demonstration
python main.py --mode demo

# This will show all networking features working together
```

## Layer-by-Layer Testing

### Physical Layer Testing

The physical layer handles the lowest level of network communication:

```bash
# Test different interfaces
python main.py --interface lo    # Loopback (default)
python main.py --interface eth0  # Ethernet (if available)

# Monitor physical layer statistics
# Check for simulation mode activation
```

**What to verify:**
- Stack starts successfully in simulation mode
- Physical layer statistics show frame transmission
- No socket permission errors in simulation mode

### Data Link Layer Testing

Tests Ethernet frame handling and MAC address management:

```bash
# Run packet sniffer to see frame details
python examples/packet_sniffer.py --show-data --duration 30

# Look for Ethernet frame information
# Verify MAC address resolution
```

**What to verify:**
- Ethernet frames show correct MAC addresses
- Frame check sequences are calculated
- ARP table is populated with local entries

### Network Layer Testing

Tests IP packet routing and ICMP functionality:

```bash
# Test ping (ICMP) functionality
python main.py --mode cli --ping 127.0.0.1
python main.py --mode cli --ping 10.0.0.1

# Test routing table management
python main.py --mode cli --routes

# Add custom route (via web interface)
# Destination: 192.168.100.0/24
# Gateway: 192.168.1.1
# Interface: eth0
```

**What to verify:**
- Ping responses show realistic round-trip times
- Routing table displays default routes
- Custom routes can be added and removed
- IP packet statistics increment properly

### Transport Layer Testing

Tests TCP reliable connections and UDP fast delivery:

#### TCP Testing

```bash
# Start TCP server
python examples/tcp_server.py --port 8080 --type echo

# In another terminal, test with client
python examples/tcp_client.py --connect 127.0.0.1 8080 --message "Hello TCP!"

# Test interactive client
python examples/tcp_client.py --interactive
```

**What to verify:**
- TCP connections establish successfully
- Messages are delivered reliably
- Connection state changes are logged
- Server handles multiple client simulation

#### UDP Testing

```bash
# Test UDP functionality through examples
python examples/udp_server.py --port 7777
python examples/udp_client.py --connect 127.0.0.1 7777 --message "Hello UDP!"
```

**What to verify:**
- UDP packets are sent without connection setup
- Fast delivery without reliability guarantees
- Port management works correctly

### Application Layer Testing

Tests HTTP and custom application protocols:

#### HTTP Server Testing

```bash
# Start HTTP server
python examples/tcp_server.py --port 8080 --type http

# Test with curl or browser
curl http://localhost:8080/
curl http://localhost:8080/status
```

**What to verify:**
- HTTP responses are properly formatted
- Different paths return appropriate content
- Server handles multiple requests

#### Web Interface Testing

```bash
# Start web interface
python main.py --mode web --port 5000

# Test all dashboard features:
# 1. Start/Stop stack
# 2. View real-time statistics
# 3. Add/remove routes
# 4. Run ping tests
# 5. Monitor packet capture
```

**What to verify:**
- All dashboard tabs load correctly
- Real-time statistics update
- Interactive features work (ping, routing)
- Packet capture shows realistic traffic

## Advanced Testing Scenarios

### 1. Stress Testing

```bash
# Generate high traffic load
python -c "
import time
from tcp_ip_stack import TCPIPStack

stack = TCPIPStack()
stack.start()

# Generate many packets rapidly
for i in range(1000):
    stack.send_packet(b'test data', '127.0.0.1')
    if i % 100 == 0:
        print(f'Sent {i} packets')

stack.stop()
"
```

### 2. Error Condition Testing

```bash
# Test invalid IP addresses
python main.py --mode cli --ping 999.999.999.999

# Test non-existent routes
# Try adding invalid routes through web interface

# Test connection limits
# Start many TCP connections simultaneously
```

### 3. Performance Testing

```bash
# Measure packet processing speed
python -c "
import time
from tcp_ip_stack import TCPIPStack

stack = TCPIPStack()
stack.start()

start_time = time.time()
packet_count = 10000

for i in range(packet_count):
    stack.send_packet(b'performance test', '127.0.0.1')

duration = time.time() - start_time
print(f'Processed {packet_count} packets in {duration:.2f} seconds')
print(f'Rate: {packet_count/duration:.0f} packets/second')

stack.stop()
"
```

## Integration Testing

### 1. Multi-Component Test

```bash
# Terminal 1: Start server
python examples/tcp_server.py --port 8080

# Terminal 2: Start packet capture  
python examples/packet_sniffer.py --protocol TCP --port 8080

# Terminal 3: Send client requests
python examples/tcp_client.py --connect 127.0.0.1 8080 --message "Integration test"

# Terminal 4: Monitor via web interface
python main.py --mode web
```

### 2. Protocol Interaction Test

```bash
# Test all protocols together
python main.py --mode demo

# Verify in logs:
# - HTTP requests and responses
# - SSH connection simulation  
# - DNS query simulation
# - ICMP ping messages
# - TCP connection management
```

## Testing Checklist

### Basic Functionality ✓
- [ ] Stack starts without errors
- [ ] Web interface loads correctly
- [ ] Statistics update in real-time
- [ ] Demo traffic generates realistic patterns

### Network Layer ✓
- [ ] Ping functionality works
- [ ] Routing table displays correctly
- [ ] Routes can be added/removed
- [ ] IP packet processing

### Transport Layer ✓
- [ ] TCP connections establish
- [ ] UDP packets transmit
- [ ] Port management works
- [ ] Connection state tracking

### Application Layer ✓
- [ ] HTTP server responds correctly
- [ ] Custom protocols work
- [ ] Web dashboard fully functional
- [ ] API endpoints respond

### Performance ✓
- [ ] No memory leaks during long runs
- [ ] Reasonable packet processing speed
- [ ] Graceful error handling
- [ ] Clean startup and shutdown

### Examples ✓
- [ ] All example scripts run successfully
- [ ] Interactive modes work
- [ ] Packet capture shows detailed info
- [ ] Server/client communication

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```
   Solution: The stack automatically falls back to simulation mode
   This is normal and expected behavior
   ```

2. **Port Already in Use**
   ```bash
   # Use different port
   python main.py --mode web --port 5001
   ```

3. **No Statistics Updating**
   ```
   Solution: Click "Start Stack" in web interface
   Check console logs for errors
   ```

4. **Import Errors**
   ```bash
   # Ensure you're in project directory
   cd tcp-ip-stack
   python main.py
   ```

### Debug Mode

```bash
# Enable detailed logging
python main.py --mode web --log-level DEBUG

# Check stack status
python main.py --mode cli --stats
```

### Performance Monitoring

```bash
# Monitor resource usage
python -c "
import psutil, time
from tcp_ip_stack import TCPIPStack

stack = TCPIPStack()
stack.start()

for i in range(10):
    process = psutil.Process()
    print(f'Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB')
    print(f'CPU: {process.cpu_percent():.1f}%')
    time.sleep(5)

stack.stop()
"
```

## Test Results Documentation

When testing, document results in this format:

```
Test: [Test Name]
Date: [Date]
Environment: [OS, Python version]
Result: [PASS/FAIL]
Notes: [Any observations]
Performance: [Speed/memory measurements if applicable]
```

Example:
```
Test: Basic TCP Connection
Date: 2024-12-20
Environment: Ubuntu 20.04, Python 3.8.10
Result: PASS
Notes: Connection established successfully, data transmitted correctly
Performance: 1000 packets/second average
```

## Automated Testing

For continuous integration, use:

```bash
# Run basic functionality tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_transport.py -v
python -m pytest tests/test_network.py -v

# Run with coverage
python -m pytest tests/ --cov=tcp_ip_stack --cov-report=html
```

This testing guide ensures comprehensive validation of all TCP/IP stack features and provides confidence in the implementation's correctness and performance.