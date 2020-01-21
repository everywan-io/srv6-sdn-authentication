#!/usr/bin/env python

# General imports
import logging
import pynat
from ipaddress import ip_address, IPv6Network, IPv4Network
from ipaddress import IPv4Interface, IPv6Interface, AddressValueError
from urllib.parse import urlparse
import socket
import time
from ping3 import ping
from pyroute2 import IPRoute
# pymerang dependencies
from pymerang import no_tunnel
from pymerang import vxlan_utils
from pymerang import etherws_utils
from pymerang import pymerang_pb2

# Tunnel modes
TUNNEL_MODES = {
    'no_tunnel': pymerang_pb2.TunnelMode.no_tunnel,
    'vxlan': pymerang_pb2.TunnelMode.vxlan,
    'etherws': pymerang_pb2.TunnelMode.etherws
}

REVERSE_TUNNEL_MODES = {v: k for k, v in TUNNEL_MODES.items()}

# NAT types
NAT_TYPES = [
    pynat.BLOCKED,
    pynat.OPEN,
    pynat.FULL_CONE,
    pynat.RESTRICTED_CONE,
    pynat.RESTRICTED_PORT,
    pynat.SYMMETRIC,
    pynat.UDP_FIREWALL
]


# Interface types
class InterfaceType:
    UNKNOWN = 'unknown'
    WAN = 'wan'
    LAN = 'lan'


# Device status
class DeviceStatus:
    NOT_CONNECTED = 'Not Connected'
    CONNECTED = 'Connected'
    RUNNING = 'Running'


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


# Get names and addresses of the interfaces
def get_local_interfaces():
    # Get pyroute2 instance
    with IPRoute() as ip_route:
        # Iterate on the interfaces
        interfaces = dict()
        for interface in ip_route.get_links():
            # Extract the index of the interface
            ifindex = interface.get('index')
            # Get the interface name
            ifname = interface.get_attr('IFLA_IFNAME')
            # Get the interface MAC address
            mac_addr = interface.get_attr('IFLA_ADDRESS')
            # Iterate on the IP addresses
            ipv4_addrs = list()
            ipv6_addrs = list()
            for addr in ip_route.get_addr(index=ifindex):
                # Get the address family
                family = addr.get('family')
                if family == socket.AF_INET:
                    # IPv4 address
                    prefixlen = addr.get('prefixlen')
                    addr = addr.get_attr('IFA_ADDRESS')
                    ipv4_addrs.append('%s/%s' % (addr, prefixlen))
                elif family == socket.AF_INET6:
                    # IPv6 address
                    prefixlen = addr.get('prefixlen')
                    addr = addr.get_attr('IFA_ADDRESS')
                    ipv6_addrs.append('%s/%s' % (addr, prefixlen))
                else:
                    # Invalid address
                    logging.error('Invalid address %s' % addr)
            # Save the interface
            interfaces[ifname] = {
                'ifindex': ifindex,
                'ifname': ifname,
                'mac_addr': mac_addr,
                'ipv4_addrs': ipv4_addrs,
                'ipv6_addrs': ipv6_addrs
            }
    # Return the interfaces
    return interfaces


# Send a ping to the dst and return the delay expressed in seconds
def send_ping(dst_ip):
    delay = ping(dst_ip)
    return delay


# Send a UDP message to the dst on the specified port
def send_keep_alive_udp(dst_ip, dst_port):
    # Discover the address family
    family = getAddressFamily(dst_ip)
    # Create the socket
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        # Send an empty UDP message to the destination
        sock.sendto(b'', (dst_ip, dst_port))


# Start sending keep alive messages using ICMP protocol
def start_keep_alive_icmp(dst_ip, interval=30, max_lost=0, callback=None):
    logging.info('Start sending ICMP keep alive messages to %s\n'
                 'Interval set to %s seconds' % (dst_ip, interval))
    current_lost = 0
    while True:
        # Returns delay in seconds.
        delay = send_ping(dst_ip)
        if max_lost > 0:
            if not delay:
                current_lost += 1
                logging.debug('Lost keep alive message (count %s)' %
                              current_lost)
                if max_lost > 0 and current_lost >= max_lost:
                    # Too many lost keep alive messages
                    if callback is not None:
                        logging.info('Too many lost keep alive messages'
                                     'Trying to reconnect to the controller')
                        return callback()
                    return None
            else:
                current_lost = 0
        # Wait for X seconds before sending the next keep alive
        time.sleep(interval)


# Start sending keep alive messages using UDP protocol
def start_keep_alive_udp(dst_ip, dst_port, interval=30):
    logging.info('Start sending UDP keep alive messages to %s port %s\n'
                 'Interval set to %s seconds' % (dst_ip, dst_port, interval))
    while True:
        # Send the keep alive message to the destination
        send_keep_alive_udp(dst_ip, dst_port)
        # Wait for X seconds before sending the next keep alive
        time.sleep(interval)


# Allocates private IPv6 addresses
class IPv6AddressAllocator(object):

    prefix = 16
    net = 'fcfa::/%d' % prefix

    def __init__(self):
        logging.debug('*** Calculating Available Private Nets')
        self.hosts = (IPv6Network(self.net)).hosts()

    def nextAddress(self):
        return next(self.hosts).__str__()


# Allocates private IPv4 addresses
class IPv4AddressAllocator(object):

    prefix = 16
    net = '169.254.0.0/%d' % prefix

    def __init__(self):
        logging.debug('*** Calculating Available Private Nets')
        self.hosts = (IPv4Network(self.net)).hosts()

    def nextAddress(self):
        return next(self.hosts).__str__()


# Allocates private IPv6 nets
class IPv6NetAllocator(object):

    bit = 16
    net = 'fcfa::/%d' % bit
    prefix = 126

    def __init__(self):
        logging.debug('*** Calculating Available Private Nets')
        self.subnets = (IPv6Network(self.net)).subnets(new_prefix=self.prefix)

    def nextNet(self):
        net = next(self.subnets)
        return net.__str__()


# Allocates private IPv4 nets
class IPv4NetAllocator(object):

    bit = 16
    net = '198.19.0.0/%d' % bit
    prefix = 30

    def __init__(self):
        logging.debug('*** Calculating Available Private Nets')
        self.subnets = (IPv4Network(self.net)).subnets(new_prefix=self.prefix)

    def nextNet(self):
        net = next(self.subnets)
        return net.__str__()


# Return IP and port from a address encoded as string
def parse_ip_port(netloc):
    try:
        ip = ip_address(netloc)
        port = None
    except ValueError:
        if netloc.startswith('ipv6:'):
            netloc = 'ipv6://' + netloc[5:]
        elif netloc.startswith('ipv4:'):
            netloc = 'ipv4://' + netloc[5:]
        parsed = urlparse(netloc)
        ip = ip_address(parsed.hostname).__str__()
        port = parsed.port
    return ip, port


class TunnelState:

    def __init__(self, controller_ip, debug=False):
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        # Tunnel modes registered
        self.tunnel_modes = dict()
        # Mapping NAT type to tunnel modes
        self.nat_to_tunnel_modes = dict()
        for nat_type in NAT_TYPES:
            self.nat_to_tunnel_modes[nat_type] = dict()
        # Save server IP
        self.controller_ip = controller_ip
        # Initialize network allocator
        self.ipv6_net_allocator = IPv6NetAllocator()
        self.ipv4_net_allocator = IPv4NetAllocator()
        # Initialize address allocator
        self.ipv6_address_allocator = IPv6AddressAllocator()
        self.ipv4_address_allocator = IPv4AddressAllocator()
        # Initialize tunnel modes
        self.init_tunnel_modes()

    # Select the best tunnel mode available for the given NAT type
    def select_tunnel_mode(self, nat_type):
        # Sort tunnel modes by priority
        available_modes = sorted(self.nat_to_tunnel_modes[nat_type])
        if len(available_modes) == 0:
            # If no tunnel mode is suitable to the NAT type,
            # return None
            return None
        # Pick the tunnel mode with the higher priority
        return self.nat_to_tunnel_modes[nat_type][available_modes[0]]

    # Register a tunnel mode
    def register_tunnel_mode(self, tunnel_mode):
        # Get the priority of the tunnel mode
        priority = tunnel_mode.priority
        for nat_type in tunnel_mode.supported_nat_types:
            if self.nat_to_tunnel_modes[nat_type].get(priority) is not None:
                tunnel_mode_bis = self.nat_to_tunnel_modes[nat_type][priority]
                logging.CRITICAL('Error: conflicting priorities for %s and %s'
                                 % (tunnel_mode.name,
                                    tunnel_mode_bis.name))
            # Associate the tunnel mode to the NAT type
            self.nat_to_tunnel_modes[nat_type][priority] = tunnel_mode
        # Save the tunnel mode
        self.tunnel_modes[tunnel_mode.name] = tunnel_mode

    # Unregister the tunnel mode
    def unregister_tunnel_mode(self, name):
        # Iterate on the NAT types
        for nat_type in self.nat_to_tunnel_modes:
            # Iterate on the tunnel modes
            tunnel_modes = self.nat_to_tunnel_modes[nat_type]
            for priority, tunnel_mode in tunnel_modes.items():
                # Look up the tunnel mode to be unregistered
                if name == tunnel_mode.name:
                    # Deassociate the tunnel mode from the NAT type
                    del self.nat_to_tunnel_modes[nat_type][priority]
        # Remove the tunnel mode
        del self.tunnel_modes[name]

    # Initialize the tunnel modes
    def init_tunnel_modes(self):
        # No tunnel (direct communication)
        self.register_tunnel_mode(no_tunnel.NoTunnel('no_tunnel', 0))
        # VLAN tunnel mode
        self.register_tunnel_mode(vxlan_utils.TunnelVXLAN(
            name='vxlan',
            priority=5,
            controller_ip=self.controller_ip,
            ipv6_address_allocator=self.ipv6_address_allocator,
            ipv4_address_allocator=self.ipv4_address_allocator)
        )
        # Ethernet over Websocket tunnel mode
        self.register_tunnel_mode(
            etherws_utils.TunnelEtherWs(
                name='etherws',
                priority=10,
                controller_ip=self.controller_ip,
                ipv6_net_allocator=self.ipv6_net_allocator,
                ipv4_net_allocator=self.ipv4_net_allocator)
        )
