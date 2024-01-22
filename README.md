# Bind 9 DNS Forwarder and DHCP server installation for local network

This script will install Bind9 and DHCP server for a local network. Bind9 will be configured as a forwarding-only DNS.

## Prerequisites
A machine (or a virtual machine) with primary interface (eth0) connected to an ISP router, and secondary interface (eth1) connected to a local network switch.

## Usage
The script must be supplied with two arguments:
 
 - A local network "prefix" (i.e., 192.168.100)
 - A local domain name (i.e., example.com)

**Example:**
```bash
bash home-lan-bind-dhcp.sh -i 192.168.100 example.com
```