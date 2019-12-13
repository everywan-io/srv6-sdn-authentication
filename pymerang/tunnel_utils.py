#!/usr/bin/env python

from ipaddress import IPv6Interface, IPv4Interface, AddressValueError
import socket


# Utiliy function to check if the IP
# is a valid IPv6 address
def validate_ipv6_address(ip):
    if ip is None:
        return False
    try:
        IPv6Interface(ip)
        return True
    except AddressValueError:
        return False


# Utiliy function to check if the IP
# is a valid IPv4 address
def validate_ipv4_address(ip):
    if ip is None:
        return False
    try:
        IPv4Interface(ip)
        return True
    except AddressValueError:
        return False


# Utiliy function to get the IP address family
def getAddressFamily(ip):
    if validate_ipv6_address(ip):
        # IPv6 address
        return socket.AF_INET6
    elif validate_ipv4_address(ip):
        # IPv4 address
        return socket.AF_INET
    else:
        # Invalid address
        return None


class TunnelMode:

    def __init__(self, name, require_keep_alive_messages, supported_nat_types,
                 priority, ipv6_net_allocator, ipv4_net_allocator):
        self.name = name
        self.require_keep_alive_messages = require_keep_alive_messages
        self.supported_nat_types = supported_nat_types
        self.priority = priority
        self.ipv6_net_allocator = ipv6_net_allocator
        self.ipv4_net_allocator = ipv4_net_allocator
        self.device_ip = dict()

    def create_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    def create_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    def get_device_ip(self, device_id):
        return self.device_ip.get(device_id)