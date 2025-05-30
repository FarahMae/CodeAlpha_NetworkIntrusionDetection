#!/usr/bin/env python3
"""
Kali Linux Network Intrusion Detection System
CodeAlpha Task 4 - Professional NIDS Implementation
Author: FarahMae
"""

import socket
import struct
import threading
import time
import json
import re
import os
import sys
import subprocess
from datetime import datetime
from collections import defaultdict, deque
import argparse

# Import scapy (already installed in Kali)
try:
    from scapy.all import *
    conf.verb = 0  # Reduce scapy verbosity
except ImportError as e:
    print(f"❌ Error importing scapy: {e}")
    print("💡 Run: pip3 install scapy")
    sys.exit(1)

class KaliNIDS:
    def __init__(self, interface="eth0", log_dir="logs"):
        self.interface = interface
        self.log_dir = log_dir
        self.running = False
        
        # Create logs directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Alert storage
        self.alerts = []
        self.statistics = {
            'total_packets': 0,
            'total_alerts': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_requests': 0,
            'blocked_ips': 0
        }
        
        # Security tracking
        self.blocked_ips = set()
        self.connection_tracker = defaultdict(lambda: defaultdict(list))
        self.packet_buffer = deque(maxlen=1000)
        self.suspicious_activities = defaultdict(int)
        
        # Detection rules and thresholds
        self.rules = {
            'port_scan': {
                'threshold': 10,
                'window': 60,
                'description': 'Multiple port connections from single source'
            },
            'ddos': {
                'threshold': 100,
                'window': 10,
                'description': 'High volume traffic to single destination'
            },
            'brute_force': {
                'threshold': 5,
                'window': 300,
                'description': 'Multiple failed login attempts'
            },
            'suspicious_ports': [4444, 5555, 6666, 31337, 12345, 1337, 8080],
            'malware_domains': [
                'malware.com', 'botnet.net', 'evil.org', 'c2server.com',
                'maliciousdomain.com', 'badsite.net'
            ],
            'sql_injection_patterns': [
                r'union\s+select',
                r'or\s+1\s*=\s*1',
                r'drop\s+table',
                r';\s*delete\s+from',
                r';\s*insert\s+into',
                r'exec\s*\(',
                r'execute\s*\(',
                r'sp_executesql'
            ],
            'xss_patterns': [
                r'<script[^>]*>',
                r'javascript:',
                r'onerror\s*=',
                r'onload\s*=',
                r'alert\s*\(',
                r'document\.cookie',
                r'eval\s*\(',
                r'fromcharcode'
            ],
            'command_injection_patterns': [
                r';\s*cat\s+',
                r';\s*ls\s+',
                r';\s*id\s*;',
                r';\s*whoami',
                r';\s*uname',
                r'\|\s*nc\s+',
                r'&\s*wget\s+',
                r'`[^`]*`'
            ]
        }
        
        # Initialize logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging files"""
        self.alert_log = os.path.join(self.log_dir, "alerts.json")
        self.statistics_log = os.path.join(self.log_dir, "statistics.json")
        self.blocked_ips_log = os.path.join(self.log_dir, "blocked_ips.txt")
        
        # Create initial log files
        with open(self.alert_log, "w") as f:
            json.dump([], f)
    
    def start_monitoring(self):
        """Start the NIDS monitoring system"""
        print("🔒 Kali Linux Network Intrusion Detection System")
        print("=" * 50)
        print(f"🔍 Monitoring interface: {self.interface}")
        print(f"📁 Log directory: {self.log_dir}")
        print(f"⚡ Detection rules loaded: {len(self.rules)} categories")
        
        self.running = True
        
        # Start background threads
        threads = [
            threading.Thread(target=self.capture_packets, daemon=True),
            threading.Thread(target=self.analyze_traffic, daemon=True),
            threading.Thread(target=self.display_statistics, daemon=True),
            threading.Thread(target=self.cleanup_old_data, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        print("✅ NIDS started successfully!")
        print("📊 Real-time monitoring active...")
        print("🛑 Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping NIDS...")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring and save final statistics"""
        self.running = False
        self.save_statistics()
        print("📊 Final statistics saved")
        print("🔒 NIDS shutdown complete")
    
    def capture_packets(self):
        """Capture and analyze network packets"""
        def packet_handler(packet):
            if not self.running:
                return
            
            try:
                self.packet_buffer.append(packet)
                self.statistics['total_packets'] += 1
                
                # Real-time packet analysis
                self.analyze_packet(packet)
                
            except Exception as e:
                print(f"❌ Packet processing error: {e}")
        
        try:
            print(f"📡 Starting packet capture on {self.interface}")
            # Use scapy to capture packets
            sniff(iface=self.interface, prn=packet_handler, store=0, stop_filter=lambda x: not self.running)
        except PermissionError:
            print("❌ Permission denied. Run with sudo:")
            print(f"   sudo python3 {sys.argv[0]} -i {self.interface}")
        except Exception as e:
            print(f"❌ Capture error: {e}")
            print("💡 Check interface name with: ip addr show")
    
    def analyze_packet(self, packet):
        """Analyze individual packets for threats"""
        current_time = time.time()
        
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # TCP Analysis
        if packet.haslayer(TCP):
            self.statistics['tcp_packets'] += 1
            self.analyze_tcp_packet(packet, current_time)
        
        # UDP Analysis
        elif packet.haslayer(UDP):
            self.statistics['udp_packets'] += 1
            self.analyze_udp_packet(packet)
        
        # ICMP Analysis
        elif packet.haslayer(ICMP):
            self.statistics['icmp_packets'] += 1
            self.analyze_icmp_packet(packet, current_time)
        
        # DNS Analysis
        if packet.haslayer(DNS):
            self.analyze_dns_packet(packet)
        
        # HTTP Analysis
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            self.analyze_http_packet(packet)
    
    def analyze_tcp_packet(self, packet, current_time):
        """Analyze TCP packets for suspicious activity"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Port scan detection (SYN packets)
        if flags == 2:  # SYN flag
            self.connection_tracker[src_ip][dst_port].append(current_time)
            
            # Clean old entries
            self.connection_tracker[src_ip][dst_port] = [
                t for t in self.connection_tracker[src_ip][dst_port]
                if current_time - t < self.rules['port_scan']['window']
            ]
            
            # Check for port scanning
            recent_ports = sum(1 for port_times in self.connection_tracker[src_ip].values() 
                             for t in port_times if current_time - t < self.rules['port_scan']['window'])
            
            if recent_ports >= self.rules['port_scan']['threshold']:
                self.create_alert(
                    "Port Scan Detected",
                    src_ip, dst_ip,
                    f"Scanned {recent_ports} ports in {self.rules['port_scan']['window']} seconds",
                    "HIGH"
                )
        
        # Suspicious port detection
        if dst_port in self.rules['suspicious_ports']:
            self.create_alert(
                "Suspicious Port Access",
                src_ip, dst_ip,
                f"Access to suspicious port {dst_port}",
                "MEDIUM"
            )
        
        # SSH brute force detection
        if dst_port == 22:
            self.suspicious_activities[f"ssh_{src_ip}_{dst_ip}"] += 1
            if self.suspicious_activities[f"ssh_{src_ip}_{dst_ip}"] >= self.rules['brute_force']['threshold']:
                self.create_alert(
                    "SSH Brute Force Attack",
                    src_ip, dst_ip,
                    f"Multiple SSH connection attempts",
                    "HIGH"
                )
    
    def analyze_udp_packet(self, packet):
        """Analyze UDP packets"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[UDP].dport
        
        # DNS amplification detection
        if dst_port == 53 and len(packet) > 512:
            self.create_alert(
                "Potential DNS Amplification",
                src_ip, dst_ip,
                f"Large DNS packet ({len(packet)} bytes)",
                "MEDIUM"
            )
    
    def analyze_icmp_packet(self, packet, current_time):
        """Analyze ICMP packets for ping sweeps"""
        if packet[ICMP].type == 8:  # Echo request
            src_ip = packet[IP].src
            self.suspicious_activities[f"ping_{src_ip}"] += 1
            
            # Reset counter every minute
            if current_time % 60 == 0:
                self.suspicious_activities[f"ping_{src_ip}"] = 0
            
            if self.suspicious_activities[f"ping_{src_ip}"] >= 10:
                self.create_alert(
                    "ICMP Ping Sweep",
                    src_ip, packet[IP].dst,
                    "Multiple ICMP echo requests detected",
                    "MEDIUM"
                )
    
    def analyze_dns_packet(self, packet):
        """Analyze DNS queries for malicious domains"""
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore').lower()
            
            for malware_domain in self.rules['malware_domains']:
                if malware_domain in query:
                    self.create_alert(
                        "Malicious Domain Query",
                        packet[IP].src, packet[IP].dst,
                        f"Query for suspicious domain: {query}",
                        "HIGH"
                    )
    
    def analyze_http_packet(self, packet):
        """Analyze HTTP traffic for web attacks"""
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if 'http' in payload or 'get ' in payload or 'post ' in payload:
                self.statistics['http_requests'] += 1
                
                # SQL Injection Detection
                for pattern in self.rules['sql_injection_patterns']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.create_alert(
                            "SQL Injection Attempt",
                            src_ip, dst_ip,
                            f"SQL injection pattern detected: {pattern}",
                            "CRITICAL"
                        )
                        break
                
                # XSS Detection
                for pattern in self.rules['xss_patterns']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.create_alert(
                            "Cross-Site Scripting (XSS)",
                            src_ip, dst_ip,
                            f"XSS pattern detected: {pattern}",
                            "HIGH"
                        )
                        break
                
                # Command Injection Detection
                for pattern in self.rules['command_injection_patterns']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.create_alert(
                            "Command Injection Attempt",
                            src_ip, dst_ip,
                            f"Command injection pattern detected: {pattern}",
                            "CRITICAL"
                        )
                        break
                
        except Exception as e:
            pass  # Ignore decoding errors
    
    def analyze_traffic(self):
        """Perform bulk traffic analysis"""
        while self.running:
            time.sleep(10)  # Analyze every 10 seconds
            
            if not self.packet_buffer:
                continue
            
            # Analyze recent packets for patterns
            recent_packets = list(self.packet_buffer)
            self.packet_buffer.clear()
            
            # DDoS detection
            self.detect_ddos(recent_packets)
            
            # Traffic anomaly detection
            self.detect_traffic_anomalies(recent_packets)
    
    def detect_ddos(self, packets):
        """Detect DDoS attacks based on traffic volume"""
        target_counts = defaultdict(int)
        source_counts = defaultdict(int)
        
        for packet in packets:
            if packet.haslayer(IP):
                target_counts[packet[IP].dst] += 1
                source_counts[packet[IP].src] += 1
        
        # Check for high volume to single target
        for target, count in target_counts.items():
            if count >= self.rules['ddos']['threshold']:
                self.create_alert(
                    "DDoS Attack Detected",
                    "Multiple Sources", target,
                    f"{count} packets to single target in analysis window",
                    "CRITICAL"
                )
        
        # Check for distributed attack from single source
        for source, count in source_counts.items():
            if count >= self.rules['ddos']['threshold']:
                self.create_alert(
                    "High Volume Attack",
                    source, "Multiple Targets",
                    f"{count} packets from single source in analysis window",
                    "HIGH"
                )
    
    def detect_traffic_anomalies(self, packets):
        """Detect traffic anomalies and patterns"""
        protocol_distribution = defaultdict(int)
        port_distribution = defaultdict(int)
        
        for packet in packets:
            if packet.haslayer(IP):
                if packet.haslayer(TCP):
                    protocol_distribution['TCP'] += 1
                    port_distribution[packet[TCP].dport] += 1
                elif packet.haslayer(UDP):
                    protocol_distribution['UDP'] += 1
                    port_distribution[packet[UDP].dport] += 1
                elif packet.haslayer(ICMP):
                    protocol_distribution['ICMP'] += 1
        
        # Detect unusual protocol distribution
        total_packets = sum(protocol_distribution.values())
        if total_packets > 50:  # Only analyze if sufficient data
            icmp_ratio = protocol_distribution['ICMP'] / total_packets
            if icmp_ratio > 0.5:  # More than 50% ICMP traffic
                self.create_alert(
                    "Unusual Traffic Pattern",
                    "Network", "Analysis",
                    f"High ICMP traffic ratio: {icmp_ratio:.2%}",
                    "MEDIUM"
                )
    
    def create_alert(self, alert_type, src_ip, dst_ip, details, severity):
        """Create and process security alerts"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'details': details,
            'severity': severity,
            'status': 'active'
        }
        
        self.alerts.append(alert)
        self.statistics['total_alerts'] += 1
        
        # Display alert in real-time
        color = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m'        # Green
        }.get(severity, '\033[0m')
        
        print(f"\n🚨 {color}[{severity}] {alert_type}\033[0m")
        print(f"   📅 {alert['timestamp']}")
        print(f"   🔗 {src_ip} → {dst_ip}")
        print(f"   📝 {details}")
        
        # Log alert to file
        self.log_alert(alert)
        
        # Automated response for critical alerts
        if severity in ['CRITICAL', 'HIGH'] and src_ip not in ['Multiple Sources', 'Network']:
            self.trigger_response(src_ip, alert)
    
    def trigger_response(self, src_ip, alert):
        """Trigger automated response to threats"""
        if src_ip in self.blocked_ips:
            return  # Already blocked
        
        try:
            # Block malicious IP using iptables
            cmd = f"iptables -A INPUT -s {src_ip} -j DROP"
            result = subprocess.run(['sudo'] + cmd.split(), 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.add(src_ip)
                self.statistics['blocked_ips'] += 1
                print(f"   🔒 Automatically blocked IP: {src_ip}")
                
                # Log blocked IP
                with open(self.blocked_ips_log, "a") as f:
                    f.write(f"{datetime.now().isoformat()} - {src_ip} - {alert['type']}\n")
            else:
                print(f"   ❌ Failed to block {src_ip}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Timeout blocking {src_ip}")
        except Exception as e:
            print(f"   ❌ Error blocking {src_ip}: {e}")
    
    def log_alert(self, alert):
        """Log alerts to JSON file"""
        try:
            # Read existing alerts
            try:
                with open(self.alert_log, "r") as f:
                    alerts = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                alerts = []
            
            # Add new alert
            alerts.append(alert)
            
            # Write back to file
            with open(self.alert_log, "w") as f:
                json.dump(alerts, f, indent=2)
                
        except Exception as e:
            print(f"❌ Error logging alert: {e}")
    
    def save_statistics(self):
        """Save current statistics to file"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'statistics': self.statistics,
                'blocked_ips': list(self.blocked_ips),
                'total_alerts_by_type': {}
            }
            
            # Count alerts by type
            for alert in self.alerts:
                alert_type = alert['type']
                stats['total_alerts_by_type'][alert_type] = stats['total_alerts_by_type'].get(alert_type, 0) + 1
            
            with open(self.statistics_log, "w") as f:
                json.dump(stats, f, indent=2)
                
        except Exception as e:
            print(f"❌ Error saving statistics: {e}")
    
    def display_statistics(self):
        """Display real-time statistics"""
        while self.running:
            time.sleep(30)  # Update every 30 seconds
            
            print(f"\n📊 === NIDS Statistics ({datetime.now().strftime('%H:%M:%S')}) ===")
            print(f"   📦 Total Packets: {self.statistics['total_packets']:,}")
            print(f"   🚨 Total Alerts: {self.statistics['total_alerts']}")
            print(f"   🔒 Blocked IPs: {self.statistics['blocked_ips']}")
            print(f"   🌐 HTTP Requests: {self.statistics['http_requests']}")
            print(f"   📡 Protocol Distribution:")
            print(f"      TCP: {self.statistics['tcp_packets']:,}")
            print(f"      UDP: {self.statistics['udp_packets']:,}")
            print(f"      ICMP: {self.statistics['icmp_packets']:,}")
            
            # Show recent alert types
            if self.alerts:
                recent_alerts = [a['type'] for a in self.alerts[-5:]]
                print(f"   🚨 Recent Alerts: {', '.join(recent_alerts)}")
    
    def cleanup_old_data(self):
        """Clean up old tracking data to prevent memory issues"""
        while self.running:
            time.sleep(300)  # Clean every 5 minutes
            
            current_time = time.time()
            
            # Clean old connection tracking data
            for src_ip in list(self.connection_tracker.keys()):
                for port in list(self.connection_tracker[src_ip].keys()):
                    self.connection_tracker[src_ip][port] = [
                        t for t in self.connection_tracker[src_ip][port]
                        if current_time - t < 3600  # Keep last hour
                    ]
                    if not self.connection_tracker[src_ip][port]:
                        del self.connection_tracker[src_ip][port]
                
                if not self.connection_tracker[src_ip]:
                    del self.connection_tracker[src_ip]

def main():
    parser = argparse.ArgumentParser(description='Kali Linux Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', default='eth0', 
                       help='Network interface to monitor (default: eth0)')
    parser.add_argument('-l', '--logdir', default='logs',
                       help='Log directory (default: logs)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return
    
    # Check if running as root for packet capture
    if os.geteuid() != 0:
        print("❌ This script requires root privileges for packet capture")
        print("💡 Run with: sudo python3 nids.py")
        return
    
    # Initialize and start NIDS
    nids = KaliNIDS(interface=args.interface, log_dir=args.logdir)
    nids.start_monitoring()

if __name__ == "__main__":
    main()
