#!/bin/bash

# Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Allow LAN (192.168.0.0/16)
iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
iptables -A INPUT  -s 192.168.0.0/16 -j ACCEPT

# Allow established/related connections (responses to LAN requests)
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block everything else (internet)
iptables -A OUTPUT -j DROP
iptables -A INPUT  -j DROP
