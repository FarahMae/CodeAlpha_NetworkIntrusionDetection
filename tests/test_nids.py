#!/usr/bin/env python3
"""
NIDS Attack Simulation and Testing Script
CodeAlpha Task 4 - Test detection capabilities
"""

import time
import subprocess
import threading
import random
import requests
from scapy.all import *
import argparse
import os

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1", interface="eth0"):
        self.target_ip = target_ip
        self.interface = interface
        self.attack_results = {}
        
    def run_all_tests(self):
        """Run comprehensive attack simulation tests"""
        print("🎯 Starting Comprehensive NIDS Testing")
        print("=" * 50)
        
        tests = [
            ("Port Scan", self.simulate_port_scan),
            ("SQL Injection", self.simulate_sql_injection),
            ("XSS Attack", self.simulate_xss_attack),
            ("Ping Sweep", self.simulate_ping_sweep),
            ("Suspicious Port Access", self.simulate_suspicious_ports),
        ]
        
        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                test_func()
                self.attack_results[test_name] = "✅ Completed"
                print(f"   ✅ {test_name} simulation completed")
            except Exception as e:
                self.attack_results[test_name] = f"❌ Error: {e}"
                print(f"   ❌ {test_name} failed: {e}")
            
            time.sleep(2)  # Wait between tests
        
        self.display_results()
    
    def simulate_port_scan(self):
        """Simulate port scanning attack"""
        print("   🔍 Simulating port scan...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995, 1433, 3389, 5432]
        
        for port in common_ports:
            try:
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=0, iface=self.interface)
                time.sleep(0.1)
            except Exception as e:
                print(f"     ⚠️ Port scan error on port {port}: {e}")
    
    def simulate_sql_injection(self):
        """Simulate SQL injection attacks"""
        print("   💉 Simulating SQL injection...")
        payloads = [
            "' UNION SELECT username, password FROM users--",
            "1' OR '1'='1'--",
            "'; DROP TABLE users; --"
        ]
        
        for payload in payloads:
            try:
                # Create raw HTTP packet with SQL injection
                http_request = f"GET /?id={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                packet = IP(dst=self.target_ip)/TCP(dport=80)/Raw(load=http_request)
                send(packet, verbose=0, iface=self.interface)
                time.sleep(0.5)
            except Exception as e:
                print(f"     ⚠️ SQL injection error: {e}")
    
    def simulate_xss_attack(self):
        """Simulate XSS attacks"""
        print("   🕷️ Simulating XSS attacks...")
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in payloads:
            try:
                http_request = f"GET /?search={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                packet = IP(dst=self.target_ip)/TCP(dport=80)/Raw(load=http_request)
                send(packet, verbose=0, iface=self.interface)
                time.sleep(0.5)
            except Exception as e:
                print(f"     ⚠️ XSS error: {e}")
    
    def simulate_ping_sweep(self):
        """Simulate ping sweep"""
        print("   📡 Simulating ping sweep...")
        ip_parts = self.target_ip.split('.')
        network_base = '.'.join(ip_parts[:3])
        
        for i in range(1, 21):
            target = f"{network_base}.{i}"
            try:
                packet = IP(dst=target)/ICMP()
                send(packet, verbose=0, iface=self.interface)
                time.sleep(0.1)
            except Exception as e:
                print(f"     ⚠️ Ping sweep error: {e}")
                break
    
    def simulate_suspicious_ports(self):
        """Simulate access to suspicious ports"""
        print("   🚪 Simulating suspicious port access...")
        suspicious_ports = [4444, 5555, 6666, 31337, 12345]
        
        for port in suspicious_ports:
            try:
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=0, iface=self.interface)
                time.sleep(0.5)
            except Exception as e:
                print(f"     ⚠️ Suspicious port error: {e}")
    
    def display_results(self):
        """Display test results"""
        print("\n📋 Test Results Summary")
        print("=" * 50)
        
        for test_name, result in self.attack_results.items():
            print(f"   {result} {test_name}")
        
        print(f"\n📊 Total Tests: {len(self.attack_results)}")
        successful = sum(1 for r in self.attack_results.values() if "✅" in r)
        print(f"📈 Successful: {successful}/{len(self.attack_results)}")

def main():
    parser = argparse.ArgumentParser(description='NIDS Testing Script')
    parser.add_argument('-t', '--target', default='127.0.0.1',
                       help='Target IP address (default: 127.0.0.1)')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("❌ This script requires root privileges")
        print("💡 Run with: sudo python3 test_nids.py")
        return
    
    simulator = AttackSimulator(args.target, args.interface)
    simulator.run_all_tests()

if __name__ == "__main__":
    main()
