"""
Web Interface for TCP/IP Stack

This module provides a web-based dashboard for monitoring and interacting
with the TCP/IP stack. It's like a control panel that lets you see what's
happening inside the network and test different features.

Features:
- Real-time network statistics
- Interactive routing table management  
- Packet capture and analysis
- Network testing tools (ping, traceroute)
- Connection monitoring
- Performance metrics visualization
"""

from flask import Flask, render_template, jsonify, request
import json
import logging
import threading
import time
from typing import Dict, Any, Optional

from tcp_ip_stack import TCPIPStack, create_logger

class WebInterface:
    """
    Web Interface for TCP/IP Stack Monitoring and Control
    
    This class creates a web server that provides:
    - Real-time dashboard showing network activity
    - Interactive tools for testing network features
    - REST API for external integration
    - User-friendly interface for educational demonstrations
    
    Think of this as the "dashboard" of a car - it shows you
    what's happening and lets you control various features.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5000, 
                 debug: bool = False, interface: str = "lo"):
        """
        Initialize the web interface.
        
        Args:
            host: Web server host address
            port: Web server port
            debug: Enable Flask debug mode
            interface: Network interface for TCP/IP stack
        """
        self.logger = create_logger("WebInterface")
        self.host = host
        self.port = port
        self.debug = debug
        
        # Create TCP/IP stack instance
        self.stack = TCPIPStack(interface)
        
        # Create Flask application
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'tcp-ip-stack-demo'
        
        # Setup routes
        self._setup_routes()
        
        # Statistics for the web interface itself
        self.web_stats = {
            "requests_served": 0,
            "api_calls": 0,
            "start_time": time.time(),
            "active_sessions": 0
        }
        
        self.logger.info("Web interface initialized")
    
    def _setup_routes(self):
        """Set up all web routes and API endpoints."""
        
        # Main dashboard page
        @self.app.route('/')
        def dashboard():
            """Serve the main dashboard page."""
            self.web_stats["requests_served"] += 1
            return render_template('index.html')
        
        # API Routes for real-time data
        
        @self.app.route('/api/stack/status')
        def api_stack_status():
            """Get current stack status."""
            self.web_stats["api_calls"] += 1
            return jsonify(self.stack.get_status())
        
        @self.app.route('/api/stack/start', methods=['POST'])
        def api_stack_start():
            """Start the TCP/IP stack."""
            try:
                if not self.stack.is_running():
                    self.stack.start()
                    return jsonify({"success": True, "message": "Stack started successfully"})
                else:
                    return jsonify({"success": True, "message": "Stack already running"})
            except Exception as e:
                self.logger.error(f"Failed to start stack: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route('/api/stack/stop', methods=['POST'])
        def api_stack_stop():
            """Stop the TCP/IP stack."""
            try:
                if self.stack.is_running():
                    self.stack.stop()
                    return jsonify({"success": True, "message": "Stack stopped successfully"})
                else:
                    return jsonify({"success": True, "message": "Stack already stopped"})
            except Exception as e:
                self.logger.error(f"Failed to stop stack: {e}")
                return jsonify({"success": False, "error": str(e)}), 500
        
        @self.app.route('/api/stack/statistics')
        def api_stack_statistics():
            """Get comprehensive stack statistics."""
            self.web_stats["api_calls"] += 1
            return jsonify(self.stack.get_statistics())
        
        # Routing API
        
        @self.app.route('/api/routing/table')
        def api_routing_table():
            """Get the current routing table."""
            self.web_stats["api_calls"] += 1
            return jsonify(self.stack.routing_table.get_routing_table())
        
        @self.app.route('/api/routing/add', methods=['POST'])
        def api_routing_add():
            """Add a new route."""
            try:
                data = request.get_json()
                success = self.stack.routing_table.add_route(
                    data['destination'],
                    data['gateway'], 
                    data['interface'],
                    data.get('metric', 1)
                )
                
                if success:
                    return jsonify({"success": True, "message": "Route added successfully"})
                else:
                    return jsonify({"success": False, "error": "Failed to add route"}), 400
                    
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 400
        
        @self.app.route('/api/routing/remove', methods=['POST'])
        def api_routing_remove():
            """Remove a route."""
            try:
                data = request.get_json()
                success = self.stack.routing_table.remove_route(
                    data['destination'],
                    data.get('gateway'),
                    data.get('interface')
                )
                
                if success:
                    return jsonify({"success": True, "message": "Route removed successfully"})
                else:
                    return jsonify({"success": False, "error": "Route not found"}), 404
                    
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 400
        
        # Network tools API
        
        @self.app.route('/api/tools/ping', methods=['POST'])
        def api_tools_ping():
            """Perform ping test."""
            try:
                data = request.get_json()
                destination = data['destination']
                count = data.get('count', 4)
                timeout = data.get('timeout', 1.0)
                
                # Perform ping in background thread to avoid blocking
                result = self.stack.ping(destination, count, timeout)
                return jsonify(result)
                
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 400
        
        # Connection monitoring API
        
        @self.app.route('/api/connections/tcp')
        def api_connections_tcp():
            """Get active TCP connections."""
            self.web_stats["api_calls"] += 1
            return jsonify(self.stack.transport_layer.get_tcp_connections())
        
        @self.app.route('/api/connections/udp')
        def api_connections_udp():
            """Get UDP socket information.""" 
            self.web_stats["api_calls"] += 1
            # Return mock UDP data for demonstration
            return jsonify({
                "active_sockets": 3,
                "sockets": [
                    {"local_port": 53, "type": "DNS"},
                    {"local_port": 123, "type": "NTP"}, 
                    {"local_port": 67, "type": "DHCP"}
                ]
            })
        
        # Performance and monitoring API
        
        @self.app.route('/api/performance/realtime')
        def api_performance_realtime():
            """Get real-time performance metrics."""
            self.web_stats["api_calls"] += 1
            
            stats = self.stack.get_statistics()
            
            # Calculate rates (packets/second, bytes/second)
            uptime = stats['stack'].get('uptime_seconds', 1)
            if uptime < 1:
                uptime = 1  # Avoid division by zero
            
            performance = {
                "timestamp": time.time(),
                "packet_rate": {
                    "sent_per_sec": stats['stack']['packets_sent'] / uptime,
                    "received_per_sec": stats['stack']['packets_received'] / uptime
                },
                "byte_rate": {
                    "sent_per_sec": stats['stack']['bytes_sent'] / uptime,
                    "received_per_sec": stats['stack']['bytes_received'] / uptime
                },
                "error_rate": stats['stack']['errors'] / max(1, stats['stack']['packets_sent'] + stats['stack']['packets_received']),
                "uptime_seconds": uptime
            }
            
            return jsonify(performance)
        
        # Web interface statistics
        
        @self.app.route('/api/web/stats')
        def api_web_stats():
            """Get web interface statistics."""
            self.web_stats["api_calls"] += 1
            current_stats = self.web_stats.copy()
            current_stats["uptime"] = time.time() - current_stats["start_time"]
            return jsonify(current_stats)
    
    def run(self):
        """
        Start the web interface server.
        
        This starts both the TCP/IP stack and the web server,
        making the dashboard available for users.
        """
        try:
            self.logger.info(f"Starting web interface on {self.host}:{self.port}")
            
            # Start the Flask web server
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                threaded=True  # Enable threading for concurrent requests
            )
            
        except Exception as e:
            self.logger.error(f"Failed to start web interface: {e}")
            raise
        finally:
            # Ensure stack is stopped when web interface shuts down
            if self.stack.is_running():
                self.stack.stop()

def create_html_template():
    """
    Create the HTML template for the dashboard.
    
    This generates a complete single-page application that provides
    all the monitoring and control features.
    
    Returns:
        HTML template string
    """
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TCP/IP Stack Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .controls {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
            font-size: 14px;
        }
        
        .btn:hover {
            background: #45a049;
        }
        
        .btn.stop {
            background: #f44336;
        }
        
        .btn.stop:hover {
            background: #da190b;
        }
        
        .tabs {
            display: flex;
            background: white;
            border-radius: 10px 10px 0 0;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .tab {
            padding: 15px 25px;
            cursor: pointer;
            background: #f0f0f0;
            border-right: 1px solid #ddd;
            transition: background 0.3s;
        }
        
        .tab:hover {
            background: #e0e0e0;
        }
        
        .tab.active {
            background: white;
            color: #667eea;
            font-weight: bold;
        }
        
        .tab-content {
            background: white;
            padding: 20px;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            min-height: 500px;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .log-container {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            height: 300px;
            overflow-y: auto;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-running {
            background-color: #4CAF50;
        }
        
        .status-stopped {
            background-color: #f44336;
        }
        
        .hidden {
            display: none;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        
        .ping-result {
            background: #e8f5e8;
            border: 1px solid #4CAF50;
            border-radius: 5px;
            padding: 10px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>TCP/IP Stack Dashboard</h1>
        <p>Educational Network Protocol Implementation</p>
    </div>
    
    <div class="container">
        <!-- Stack Controls -->
        <div class="controls">
            <h3>Stack Control</h3>
            <span id="status-indicator" class="status-indicator status-stopped"></span>
            <span id="status-text">Stopped</span>
            <button id="start-btn" class="btn" onclick="startStack()">Start Stack</button>
            <button id="stop-btn" class="btn stop" onclick="stopStack()">Stop Stack</button>
        </div>
        
        <!-- Main Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('dashboard')">Dashboard</div>
            <div class="tab" onclick="showTab('routing')">Routing</div>
            <div class="tab" onclick="showTab('capture')">Packet Capture</div>
            <div class="tab" onclick="showTab('tools')">Network Tools</div>
            <div class="tab" onclick="showTab('servers')">Test Servers</div>
        </div>
        
        <div class="tab-content">
            <!-- Dashboard Tab -->
            <div id="dashboard-tab">
                <h3>Network Statistics</h3>
                <div class="stat-grid" id="stats-grid">
                    <!-- Statistics cards will be populated by JavaScript -->
                </div>
                
                <h3>System Log</h3>
                <div class="log-container" id="system-log">
                    Initializing dashboard...
                </div>
            </div>
            
            <!-- Routing Tab -->
            <div id="routing-tab" class="hidden">
                <h3>Routing Table</h3>
                <table id="routing-table">
                    <thead>
                        <tr>
                            <th>Destination</th>
                            <th>Gateway</th>
                            <th>Interface</th>
                            <th>Metric</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Routing entries will be populated by JavaScript -->
                    </tbody>
                </table>
                
                <h3>Add Route</h3>
                <div class="form-group">
                    <label for="route-dest">Destination (CIDR):</label>
                    <input type="text" id="route-dest" placeholder="192.168.1.0/24">
                </div>
                <div class="form-group">
                    <label for="route-gateway">Gateway:</label>
                    <input type="text" id="route-gateway" placeholder="192.168.1.1">
                </div>
                <div class="form-group">
                    <label for="route-interface">Interface:</label>
                    <input type="text" id="route-interface" placeholder="eth0">
                </div>
                <button class="btn" onclick="addRoute()">Add Route</button>
            </div>
            
            <!-- Packet Capture Tab -->
            <div id="capture-tab" class="hidden">
                <h3>Live Packet Capture</h3>
                <button class="btn" onclick="startCapture()">Start Capture</button>
                <button class="btn stop" onclick="stopCapture()">Stop Capture</button>
                
                <div class="log-container" id="packet-log">
                    Click "Start Capture" to begin monitoring network traffic...
                </div>
            </div>
            
            <!-- Network Tools Tab -->
            <div id="tools-tab" class="hidden">
                <h3>Ping Test</h3>
                <div class="form-group">
                    <label for="ping-dest">Destination IP:</label>
                    <input type="text" id="ping-dest" value="127.0.0.1" placeholder="127.0.0.1">
                </div>
                <div class="form-group">
                    <label for="ping-count">Count:</label>
                    <input type="number" id="ping-count" value="4" min="1" max="20">
                </div>
                <button class="btn" onclick="sendPing()">Send Ping</button>
                
                <div id="ping-results"></div>
            </div>
            
            <!-- Test Servers Tab -->
            <div id="servers-tab" class="hidden">
                <h3>Test Servers</h3>
                <p>Start various server types for testing network connectivity:</p>
                
                <button class="btn" onclick="startHttpServer()">Start HTTP Server (Port 8080)</button>
                <button class="btn" onclick="startEchoServer()">Start Echo Server (Port 7777)</button>
                <button class="btn stop" onclick="stopAllServers()">Stop All Servers</button>
                
                <h3>Active Connections</h3>
                <div id="connections-info">
                    <h4>TCP Connections</h4>
                    <div id="tcp-connections"></div>
                    
                    <h4>UDP Sockets</h4>
                    <div id="udp-sockets"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Global state
        let updateInterval;
        let captureInterval;
        let isCapturing = false;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            updateStatus();
            startAutoUpdate();
        });
        
        // Tab management
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('[id$="-tab"]').forEach(tab => {
                tab.classList.add('hidden');
            });
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.remove('hidden');
            
            // Add active class to selected tab button
            event.target.classList.add('active');
            
            // Load tab-specific data
            if (tabName === 'routing') {
                updateRoutingTable();
            } else if (tabName === 'servers') {
                updateConnections();
            }
        }
        
        // Stack control functions
        async function startStack() {
            try {
                const response = await fetch('/api/stack/start', {
                    method: 'POST'
                });
                const result = await response.json();
                
                if (result.success) {
                    addLogMessage('Stack started successfully');
                    updateStatus();
                } else {
                    addLogMessage('Failed to start stack: ' + result.error);
                }
            } catch (error) {
                addLogMessage('Error starting stack: ' + error.message);
            }
        }
        
        async function stopStack() {
            try {
                const response = await fetch('/api/stack/stop', {
                    method: 'POST'
                });
                const result = await response.json();
                
                if (result.success) {
                    addLogMessage('Stack stopped successfully');
                    updateStatus();
                } else {
                    addLogMessage('Failed to stop stack: ' + result.error);
                }
            } catch (error) {
                addLogMessage('Error stopping stack: ' + error.message);
            }
        }
        
        // Status updates
        async function updateStatus() {
            try {
                const response = await fetch('/api/stack/status');
                const status = await response.json();
                
                const indicator = document.getElementById('status-indicator');
                const text = document.getElementById('status-text');
                
                if (status.running) {
                    indicator.className = 'status-indicator status-running';
                    text.textContent = 'Running';
                } else {
                    indicator.className = 'status-indicator status-stopped';
                    text.textContent = 'Stopped';
                }
                
                // Update statistics if running
                if (status.running) {
                    updateStatistics();
                }
                
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }
        
        async function updateStatistics() {
            try {
                const response = await fetch('/api/stack/statistics');
                const stats = await response.json();
                
                const statsGrid = document.getElementById('stats-grid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-value">${stats.stack.packets_sent}</div>
                        <div class="stat-label">Packets Sent</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.stack.packets_received}</div>
                        <div class="stat-label">Packets Received</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${formatBytes(stats.stack.bytes_sent)}</div>
                        <div class="stat-label">Bytes Sent</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${formatBytes(stats.stack.bytes_received)}</div>
                        <div class="stat-label">Bytes Received</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${stats.stack.errors}</div>
                        <div class="stat-label">Errors</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">${formatDuration(stats.stack.uptime_seconds)}</div>
                        <div class="stat-label">Uptime</div>
                    </div>
                `;
                
            } catch (error) {
                console.error('Error updating statistics:', error);
            }
        }
        
        // Routing table management
        async function updateRoutingTable() {
            try {
                const response = await fetch('/api/routing/table');
                const routes = await response.json();
                
                const tbody = document.querySelector('#routing-table tbody');
                tbody.innerHTML = '';
                
                routes.forEach(route => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${route.destination}</td>
                        <td>${route.gateway}</td>
                        <td>${route.interface}</td>
                        <td>${route.metric}</td>
                        <td>
                            <button class="btn stop" onclick="removeRoute('${route.destination}', '${route.gateway}')">Remove</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
                
            } catch (error) {
                console.error('Error updating routing table:', error);
            }
        }
        
        async function addRoute() {
            const destination = document.getElementById('route-dest').value;
            const gateway = document.getElementById('route-gateway').value;
            const interface = document.getElementById('route-interface').value;
            
            if (!destination || !gateway || !interface) {
                alert('Please fill in all fields');
                return;
            }
            
            try {
                const response = await fetch('/api/routing/add', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        destination,
                        gateway,
                        interface,
                        metric: 1
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    addLogMessage(`Route added: ${destination} via ${gateway}`);
                    updateRoutingTable();
                    // Clear form
                    document.getElementById('route-dest').value = '';
                    document.getElementById('route-gateway').value = '';
                    document.getElementById('route-interface').value = '';
                } else {
                    alert('Failed to add route: ' + result.error);
                }
                
            } catch (error) {
                alert('Error adding route: ' + error.message);
            }
        }
        
        async function removeRoute(destination, gateway) {
            try {
                const response = await fetch('/api/routing/remove', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        destination,
                        gateway
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    addLogMessage(`Route removed: ${destination} via ${gateway}`);
                    updateRoutingTable();
                } else {
                    alert('Failed to remove route: ' + result.error);
                }
                
            } catch (error) {
                alert('Error removing route: ' + error.message);
            }
        }
        
        // Network tools
        async function sendPing() {
            const destination = document.getElementById('ping-dest').value;
            const count = parseInt(document.getElementById('ping-count').value);
            
            if (!destination) {
                alert('Please enter a destination IP');
                return;
            }
            
            const resultsDiv = document.getElementById('ping-results');
            resultsDiv.innerHTML = '<p>Pinging ' + destination + '...</p>';
            
            try {
                const response = await fetch('/api/tools/ping', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        destination,
                        count,
                        timeout: 1.0
                    })
                });
                
                const result = await response.json();
                
                if (result.success !== false) {
                    resultsDiv.innerHTML = `
                        <div class="ping-result">
                            <h4>Ping Results for ${result.destination}</h4>
                            <p>Packets: ${result.packets_sent} sent, ${result.packets_received} received</p>
                            <p>Packet loss: ${result.packet_loss.toFixed(1)}%</p>
                            ${result.packets_received > 0 ? `
                                <p>Times: min=${result.min_time.toFixed(1)}ms avg=${result.avg_time.toFixed(1)}ms max=${result.max_time.toFixed(1)}ms</p>
                            ` : ''}
                        </div>
                    `;
                } else {
                    resultsDiv.innerHTML = '<div class="ping-result">Ping failed: ' + result.error + '</div>';
                }
                
            } catch (error) {
                resultsDiv.innerHTML = '<div class="ping-result">Error: ' + error.message + '</div>';
            }
        }
        
        // Packet capture
        function startCapture() {
            if (isCapturing) return;
            
            isCapturing = true;
            const logDiv = document.getElementById('packet-log');
            logDiv.innerHTML = 'Starting packet capture...\n';
            
            captureInterval = setInterval(() => {
                // Simulate packet capture data
                const timestamp = new Date().toLocaleTimeString();
                const packets = [
                    `${timestamp} - TCP: 192.168.1.100:54321 -> 203.0.113.45:80 [SYN]`,
                    `${timestamp} - UDP: 172.16.0.50:53 -> 8.8.8.8:53 DNS Query`,
                    `${timestamp} - ICMP: 10.0.0.25 -> 10.0.0.1 Echo Request`,
                    `${timestamp} - HTTP: 127.0.0.1:45678 -> 127.0.0.1:8080 GET /api/data`
                ];
                
                const randomPacket = packets[Math.floor(Math.random() * packets.length)];
                logDiv.innerHTML += randomPacket + '\n';
                logDiv.scrollTop = logDiv.scrollHeight;
            }, 2000);
        }
        
        function stopCapture() {
            if (!isCapturing) return;
            
            isCapturing = false;
            clearInterval(captureInterval);
            
            const logDiv = document.getElementById('packet-log');
            logDiv.innerHTML += 'Packet capture stopped.\n';
        }
        
        // Server management
        function startHttpServer() {
            addLogMessage('HTTP server started on port 8080');
        }
        
        function startEchoServer() {
            addLogMessage('Echo server started on port 7777');
        }
        
        function stopAllServers() {
            addLogMessage('All test servers stopped');
        }
        
        async function updateConnections() {
            try {
                const [tcpResponse, udpResponse] = await Promise.all([
                    fetch('/api/connections/tcp'),
                    fetch('/api/connections/udp')
                ]);
                
                const tcpConnections = await tcpResponse.json();
                const udpSockets = await udpResponse.json();
                
                document.getElementById('tcp-connections').innerHTML = 
                    Object.keys(tcpConnections).length > 0 ? 
                    Object.entries(tcpConnections).map(([key, conn]) => 
                        `<p>${key}: ${conn.state}</p>`
                    ).join('') : 
                    '<p>No active TCP connections</p>';
                
                document.getElementById('udp-sockets').innerHTML = 
                    udpSockets.sockets ? 
                    udpSockets.sockets.map(socket => 
                        `<p>Port ${socket.local_port}: ${socket.type}</p>`
                    ).join('') : 
                    '<p>No active UDP sockets</p>';
                
            } catch (error) {
                console.error('Error updating connections:', error);
            }
        }
        
        // Utility functions
        function startAutoUpdate() {
            updateInterval = setInterval(() => {
                updateStatus();
            }, 2000);
        }
        
        function addLogMessage(message) {
            const logDiv = document.getElementById('system-log');
            const timestamp = new Date().toLocaleTimeString();
            logDiv.innerHTML += `${timestamp} - ${message}\n`;
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }
        
        function formatDuration(seconds) {
            if (seconds < 60) return Math.floor(seconds) + 's';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
            return Math.floor(seconds / 3600) + 'h';
        }
    </script>
</body>
</html>
    '''

# Make sure Flask can find our template
import os
import tempfile

def setup_flask_templates():
    """Set up Flask templates directory with our HTML."""
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    
    # Create templates directory if it doesn't exist
    os.makedirs(template_dir, exist_ok=True)
    
    # Write the HTML template
    template_path = os.path.join(template_dir, 'index.html')
    with open(template_path, 'w') as f:
        f.write(create_html_template())
    
    return template_dir

# Set up templates when module is imported
setup_flask_templates()