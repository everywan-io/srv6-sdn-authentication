#!/usr/bin/env python

from ipaddress import ip_address, IPv6Network, IPv4Network
from ipaddress import IPv4Interface, IPv6Interface, AddressValueError
from urllib.parse import urlparse
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni
import socket
import time
from ping3 import ping

#from pymerang import nat_utils
from nat_utils.nat_discovery_server import NAT_TYPES
from pymerang import no_tunnel
from pymerang import vxlan_utils
from pymerang import etherws_utils

from pymerang import pymerang_pb2

TUNNEL_MODES = {
    'no_tunnel': pymerang_pb2.TunnelMode.no_tunnel,
    'vxlan': pymerang_pb2.TunnelMode.vxlan,
    'etherws': pymerang_pb2.TunnelMode.etherws
}

REVERSE_TUNNEL_MODES = {v: k for k, v in TUNNEL_MODES.items()}

'''
def parse_ip_port(netloc):
    try:
        ip = ip_address(netloc)
        port = None
    except ValueError:
        parsed = urlparse('//{}'.format(netloc))
        ip = ip_address(parsed.hostname)
        port = parsed.port
    return ip, port
'''


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


def get_local_interfaces():
    interfaces = dict()
    for ifname in ni.interfaces():
        interfaces[ifname] = dict()
        # Get layer 2 information
        interfaces[ifname]['mac_addrs'] = list()
        mac_addrs = ni.ifaddresses(ifname).get(AF_LINK, [])
        for mac_addr in mac_addrs:
            broadcast = mac_addr.get('broadcast')
            addr = mac_addr.get('addr')
            interfaces[ifname]['mac_addrs'].append({
                'broadcast': broadcast,
                'addr': addr
            })
        # Get layer 3 information
        interfaces[ifname]['ipv4_addrs'] = list()
        ipv4_addrs = ni.ifaddresses(ifname).get(AF_INET, [])
        for ipv4_addr in ipv4_addrs:
            broadcast = ipv4_addr.get('broadcast')
            netmask = ipv4_addr.get('netmask')
            addr = ipv4_addr.get('addr')
            interfaces[ifname]['ipv4_addrs'].append({
                'broadcast': broadcast,
                'netmask': netmask,
                'addr': addr
            })
        interfaces[ifname]['ipv6_addrs'] = list()
        ipv6_addrs = ni.ifaddresses(ifname).get(AF_INET6, [])
        for ipv6_addr in ipv6_addrs:
            broadcast = ipv6_addr.get('broadcast')
            netmask = ipv6_addr.get('netmask')
            addr = ipv6_addr.get('addr')
            interfaces[ifname]['ipv6_addrs'].append({
                'broadcast': broadcast,
                'netmask': netmask,
                'addr': addr
            })
    return interfaces


def send_ping(dst_ip):
    # Returns delay in seconds
    delay = ping(dst_ip)
    return delay


def send_keep_alive_udp(dst_ip, dst_port):
    # Create the socket
    family = getAddressFamily(dst_ip)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        #print('Sending message to %s on port %s' % (dst_ip, dst_port))
        # Send an empty UDP message
        sock.sendto(b'', (dst_ip, dst_port))


def start_keep_alive_icmp(dst_ip, interval=30, max_lost=0, callback=None):
    print('ICMP PING\n\n\n')
    print(dst_ip)
    print(interval)
    print(max_lost)
    print(callback)
    current_lost = 0
    while True:
        # Returns delay in seconds.
        delay = send_ping(dst_ip)
        if max_lost > 0:
            if not delay:
                print('failure')
                current_lost += 1
                if current_lost >= max_lost:
                    if callback is not None:
                        #logging.info('Connection lost')
                        print('Connection lost')
                        print('callback')
                        callback()
                    current_lost = 0
            else:
                current_lost = 0
        time.sleep(interval)


def start_keep_alive_udp(dst_ip, dst_port, interval=30):
    while True:
        send_keep_alive_udp(dst_ip, dst_port)
        time.sleep(interval)


# Allocates private IPv6 nets
class IPv6NetAllocator(object):

  bit = 16
  net = 'fcfa::/%d' % bit
  prefix = 126

  def __init__(self): 
    print('*** Calculating Available Private Nets')
    self.subnets = (IPv6Network(self.net)).subnets(new_prefix=self.prefix)
  
  def nextNet(self):
    net = next(self.subnets)
    return net.__str__()


# Allocates private IPv4 nets
class IPv4NetAllocator(object):

  bit = 8
  net = '172.0.0.0/%d' % bit
  prefix = 30

  def __init__(self): 
    print('*** Calculating Available Private Nets')
    self.subnets = (IPv4Network(self.net)).subnets(new_prefix=self.prefix)
  
  def nextNet(self):
    net = next(self.subnets)
    return net.__str__()


def parse_ip_port(netloc):
    try:
        ip = ip_address(netloc)
        port = None
    except ValueError:
        if netloc.startswith('ipv6:'):
            netloc = 'ipv6://' + netloc[5:]
        elif netloc.startswith('ipv4:'):
            netloc = 'ipv4://' + netloc[5:]
        #parsed = urlparse('//{}'.format(netloc))
        parsed = urlparse(netloc)
        ip = ip_address(parsed.hostname).__str__()
        port = parsed.port
    return ip, port


class TunnelState:

    def __init__(self, server_ip):
        self.tunnel_modes = dict()
        self.nat_to_tunnel_modes = dict()
        for nat_type in NAT_TYPES:
            self.nat_to_tunnel_modes[nat_type] = dict()
        # Save server IP
        self.server_ip = server_ip
        # Initialize network allocator
        self.ipv6_net_allocator = IPv6NetAllocator()
        self.ipv4_net_allocator = IPv4NetAllocator()
        # Initialize tunnel modes
        self.init_nat_to_tunnel_modes()

    def select_tunnel_mode(self, nat_type):
        available_modes = sorted(self.nat_to_tunnel_modes[nat_type])
        if len(available_modes) == 0:
            pass # TODO
        return self.nat_to_tunnel_modes[nat_type][available_modes[0]]

    def register_tunnel_mode(self, tunnel_mode):
        priority = tunnel_mode.priority
        for nat_type in tunnel_mode.supported_nat_types:
            if self.nat_to_tunnel_modes[nat_type].get(priority) is not None:
                print('Error: conflicting priorities')
            self.nat_to_tunnel_modes[nat_type][priority] = tunnel_mode
        self.tunnel_modes[tunnel_mode.name] = tunnel_mode

    def unregister_tunnel_mode(self, name):
        for nat_type in self.nat_to_tunnel_modes:
            for priority, tunnel_mode in self.nat_to_tunnel_modes[nat_type].iter_values():
                if name == tunnel_mode.name:
                    del self.nat_to_tunnel_modes[nat_type][priority]
        del self.tunnel_modes[name]

    def init_nat_to_tunnel_modes(self):
        self.register_tunnel_mode(no_tunnel.NoTunnel('no_tunnel', 0))
        self.register_tunnel_mode(vxlan_utils.TunnelVXLAN(
            'vxlan', 5, self.server_ip, self.ipv6_net_allocator, self.ipv4_net_allocator)
        )
        self.register_tunnel_mode(
            etherws_utils.TunnelEtherWs('etherws', 10, self.server_ip, self.ipv6_net_allocator, self.ipv4_net_allocator)
        )
