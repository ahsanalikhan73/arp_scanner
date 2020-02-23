#!/usr/bin/env python
import scapy.all as scapy

def scan(ip):
    hosts = scapy.arping(ip)    # You can't play or modify with packets
    print(hosts)

scan('192.168.0.1/24')