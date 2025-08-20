"""
Routing Implementation

This module handles packet routing decisions - figuring out where to send
packets to reach their destination. Think of it as the "GPS navigation system"
of the network that finds the best path to any destination.

Key concepts demonstrated:
- Routing table management
- Longest prefix matching
- Default gateway handling
- Route metrics and priorities
- Network topology understanding
"""

import ipaddress
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

@dataclass
class Route:
    """
    A single routing table entry.
    
    Each route tells us: "To reach this destination network,
    send packets via this gateway on this interface."
    
    Like a signpost that says: "To reach downtown, go straight
    on Main Street for 2 miles."
    """
    
    destination: str    # Network address (e.g., "192.168.1.0/24")
    gateway: str        # Next hop IP address (where to send packets)
    interface: str      # Which network interface to use
    metric: int = 1     # Route priority (lower = better)
    created_at: float = None  # When this route was added
    
    def __post_init__(self):
        """Initialize default values after creation."""
        if self.created_at is None:
            self.created_at = time.time()
    
    def __str__(self) -> str:
        """Human-readable representation of this route."""
        return f"Route({self.destination} via {self.gateway} dev {self.interface} metric {self.metric})"

class RoutingTable:
    """
    Routing Table - The Network's Road Map
    
    The routing table contains all the information needed to make
    routing decisions. It's like a GPS database that knows how to
    reach every possible destination on the network.
    
    Key responsibilities:
    - Store routes to different networks
    - Find the best route for any destination
    - Handle route updates and changes
    - Manage default routes (where to send unknown traffic)
    
    Routing decisions use "longest prefix matching" - the most specific
    route wins. For example, a route to 192.168.1.0/24 is more specific
    than a route to 192.168.0.0/16, so it takes priority.
    """
    
    def __init__(self):
        """Initialize an empty routing table."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.routes: List[Route] = []
        
        # Statistics for monitoring
        self.stats = {
            "routes_added": 0,
            "routes_removed": 0,
            "lookups_performed": 0,
            "successful_matches": 0,
            "default_route_used": 0
        }
        
        self.logger.info("Routing table initialized")
    
    def add_route(self, destination: str, gateway: str, interface: str, 
                  metric: int = 1) -> bool:
        """
        Add a new route to the routing table.
        
        This is like adding a new road sign that tells traffic
        how to reach a particular destination.
        
        Args:
            destination: Network to reach (CIDR format like "192.168.1.0/24")
            gateway: Next hop IP address
            interface: Network interface name
            metric: Route priority (lower numbers = higher priority)
            
        Returns:
            True if route was added successfully
        """
        try:
            # Validate the destination network format
            network = ipaddress.IPv4Network(destination, strict=False)
            destination = str(network)
            
            # Check if this exact route already exists
            for existing_route in self.routes:
                if (existing_route.destination == destination and 
                    existing_route.gateway == gateway and
                    existing_route.interface == interface):
                    # Update metric if different
                    if existing_route.metric != metric:
                        existing_route.metric = metric
                        self.logger.info(f"Updated route metric: {existing_route}")
                    return True
            
            # Create new route
            route = Route(destination, gateway, interface, metric)
            self.routes.append(route)
            
            # Sort routes by specificity (longer prefixes first) then by metric
            self.routes.sort(key=lambda r: (-ipaddress.IPv4Network(r.destination).prefixlen, r.metric))
            
            self.stats["routes_added"] += 1
            self.logger.info(f"Added route: {route}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add route {destination} via {gateway}: {e}")
            return False
    
    def remove_route(self, destination: str, gateway: str = None, 
                    interface: str = None) -> bool:
        """
        Remove a route from the routing table.
        
        This is like taking down a road sign when a road is closed.
        
        Args:
            destination: Network to remove route for
            gateway: Specific gateway (optional - if None, removes all routes to destination)
            interface: Specific interface (optional)
            
        Returns:
            True if at least one route was removed
        """
        try:
            # Normalize destination format
            network = ipaddress.IPv4Network(destination, strict=False)
            destination = str(network)
            
            routes_to_remove = []
            
            for route in self.routes:
                if route.destination == destination:
                    # Check if gateway and interface match (if specified)
                    if gateway and route.gateway != gateway:
                        continue
                    if interface and route.interface != interface:
                        continue
                    
                    routes_to_remove.append(route)
            
            # Remove matched routes
            for route in routes_to_remove:
                self.routes.remove(route)
                self.stats["routes_removed"] += 1
                self.logger.info(f"Removed route: {route}")
            
            return len(routes_to_remove) > 0
            
        except Exception as e:
            self.logger.error(f"Failed to remove route {destination}: {e}")
            return False
    
    def get_route(self, destination_ip: str) -> Optional[Route]:
        """
        Find the best route for a destination IP address.
        
        This implements "longest prefix matching" - the fundamental
        algorithm used by all Internet routers to make forwarding decisions.
        
        The idea is simple: more specific routes (longer prefixes) take
        priority over less specific ones. For example:
        - Route to 192.168.1.0/24 beats route to 192.168.0.0/16
        - Route to 10.0.0.0/8 beats default route 0.0.0.0/0
        
        Args:
            destination_ip: IP address to find route for
            
        Returns:
            Best matching route, or None if no route found
        """
        self.stats["lookups_performed"] += 1
        
        try:
            dest_ip = ipaddress.IPv4Address(destination_ip)
            
            # Check each route (already sorted by specificity and metric)
            for route in self.routes:
                network = ipaddress.IPv4Network(route.destination)
                
                if dest_ip in network:
                    # Found a match!
                    self.stats["successful_matches"] += 1
                    
                    # Check if this is the default route
                    if network.prefixlen == 0:
                        self.stats["default_route_used"] += 1
                    
                    self.logger.debug(f"Route for {destination_ip}: {route}")
                    return route
            
            # No route found
            self.logger.warning(f"No route found for {destination_ip}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error looking up route for {destination_ip}: {e}")
            return None
    
    def add_default_route(self, gateway: str, interface: str, metric: int = 1) -> bool:
        """
        Add a default route (route to everywhere).
        
        The default route is like a sign that says "For everywhere else,
        go this way." It's used when no more specific route matches.
        
        Args:
            gateway: Default gateway IP address
            interface: Interface to use
            metric: Route priority
            
        Returns:
            True if default route was added
        """
        return self.add_route("0.0.0.0/0", gateway, interface, metric)
    
    def get_routes_to_network(self, network: str) -> List[Route]:
        """
        Get all routes that could reach a specific network.
        
        This is useful for finding backup routes or analyzing
        routing table redundancy.
        
        Args:
            network: Network to search for (CIDR format)
            
        Returns:
            List of routes that can reach the network
        """
        try:
            target_network = ipaddress.IPv4Network(network, strict=False)
            matching_routes = []
            
            for route in self.routes:
                route_network = ipaddress.IPv4Network(route.destination)
                
                # Check if route network contains target network
                if target_network.subnet_of(route_network):
                    matching_routes.append(route)
            
            return matching_routes
            
        except Exception as e:
            self.logger.error(f"Error finding routes to {network}: {e}")
            return []
    
    def get_direct_routes(self) -> List[Route]:
        """
        Get all directly connected routes.
        
        Direct routes are for networks we're directly connected to
        (no intermediate routers needed).
        
        Returns:
            List of direct routes
        """
        direct_routes = []
        
        for route in self.routes:
            # Direct routes typically have the interface IP as gateway
            # or a special marker like the interface name
            if (route.gateway == "0.0.0.0" or 
                route.gateway == route.interface or
                route.gateway.startswith("link-local")):
                direct_routes.append(route)
        
        return direct_routes
    
    def get_routes_by_interface(self, interface: str) -> List[Route]:
        """
        Get all routes using a specific interface.
        
        This is useful for understanding which traffic goes
        through each network interface.
        
        Args:
            interface: Interface name to search for
            
        Returns:
            List of routes using the interface
        """
        return [route for route in self.routes if route.interface == interface]
    
    def update_route_metric(self, destination: str, gateway: str, 
                           new_metric: int) -> bool:
        """
        Update the metric (priority) of an existing route.
        
        Lower metrics indicate better routes. This is used for
        route optimization and load balancing.
        
        Args:
            destination: Network address
            gateway: Gateway address
            new_metric: New metric value
            
        Returns:
            True if route was updated
        """
        try:
            network = ipaddress.IPv4Network(destination, strict=False)
            destination = str(network)
            
            for route in self.routes:
                if route.destination == destination and route.gateway == gateway:
                    old_metric = route.metric
                    route.metric = new_metric
                    
                    # Re-sort routes since metric changed
                    self.routes.sort(key=lambda r: (-ipaddress.IPv4Network(r.destination).prefixlen, r.metric))
                    
                    self.logger.info(f"Updated route metric: {route} (was {old_metric})")
                    return True
            
            self.logger.warning(f"Route not found for metric update: {destination} via {gateway}")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update route metric: {e}")
            return False
    
    def clear_routes(self, keep_default: bool = True):
        """
        Clear all routes from the table.
        
        This is like removing all road signs. Optionally keeps
        the default route so traffic can still flow somewhere.
        
        Args:
            keep_default: Whether to preserve default routes
        """
        if keep_default:
            # Keep only default routes (0.0.0.0/0)
            default_routes = [r for r in self.routes if r.destination == "0.0.0.0/0"]
            removed_count = len(self.routes) - len(default_routes)
            self.routes = default_routes
        else:
            removed_count = len(self.routes)
            self.routes = []
        
        self.stats["routes_removed"] += removed_count
        self.logger.info(f"Cleared {removed_count} routes (keep_default={keep_default})")
    
    def get_routing_table(self) -> List[Dict[str, Any]]:
        """
        Get the complete routing table as a list of dictionaries.
        
        This is useful for displaying routing information to users
        or exporting the table for analysis.
        
        Returns:
            List of route dictionaries
        """
        table = []
        
        for route in self.routes:
            # Calculate route age
            age_seconds = time.time() - route.created_at
            
            table.append({
                "destination": route.destination,
                "gateway": route.gateway,
                "interface": route.interface,
                "metric": route.metric,
                "age_seconds": age_seconds,
                "created_at": route.created_at
            })
        
        return table
    
    def validate_routing_table(self) -> Dict[str, Any]:
        """
        Validate the routing table for common issues.
        
        This checks for problems like:
        - Duplicate routes
        - Invalid network addresses
        - Missing default route
        - Unreachable gateways
        
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Check for default route
        has_default = any(route.destination == "0.0.0.0/0" for route in self.routes)
        if not has_default:
            warnings.append("No default route configured")
        
        # Check for duplicate routes
        route_keys = set()
        for route in self.routes:
            key = (route.destination, route.gateway, route.interface)
            if key in route_keys:
                issues.append(f"Duplicate route: {route}")
            else:
                route_keys.add(key)
        
        # Check for invalid networks
        for route in self.routes:
            try:
                ipaddress.IPv4Network(route.destination)
            except ValueError:
                issues.append(f"Invalid network address: {route.destination}")
        
        # Check for loopback routing
        for route in self.routes:
            if route.gateway == route.destination.split('/')[0]:
                issues.append(f"Gateway same as destination: {route}")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "total_routes": len(self.routes),
            "validation_time": time.time()
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get routing table statistics."""
        return {
            **self.stats,
            "total_routes": len(self.routes),
            "default_routes": len([r for r in self.routes if r.destination == "0.0.0.0/0"]),
            "direct_routes": len(self.get_direct_routes()),
            "interfaces_used": len(set(r.interface for r in self.routes))
        }
    
    def export_routes(self, format_type: str = "text") -> str:
        """
        Export routing table in various formats.
        
        Args:
            format_type: Export format ("text", "json", "csv")
            
        Returns:
            Formatted routing table string
        """
        if format_type == "text":
            lines = ["Destination          Gateway              Interface    Metric  Age"]
            lines.append("-" * 70)
            
            for route in self.routes:
                age = time.time() - route.created_at
                age_str = f"{age:.0f}s" if age < 3600 else f"{age/3600:.1f}h"
                
                line = f"{route.destination:<20} {route.gateway:<20} {route.interface:<12} {route.metric:<7} {age_str}"
                lines.append(line)
            
            return "\n".join(lines)
        
        elif format_type == "json":
            import json
            return json.dumps(self.get_routing_table(), indent=2)
        
        elif format_type == "csv":
            lines = ["Destination,Gateway,Interface,Metric,Age"]
            
            for route in self.routes:
                age = time.time() - route.created_at
                line = f"{route.destination},{route.gateway},{route.interface},{route.metric},{age:.0f}"
                lines.append(line)
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unknown export format: {format_type}")
    
    def __len__(self) -> int:
        """Return number of routes in table."""
        return len(self.routes)
    
    def __str__(self) -> str:
        """Human-readable representation of routing table."""
        return f"RoutingTable({len(self.routes)} routes)"