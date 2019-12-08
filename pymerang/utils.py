#!/usr/bin/env python

from ipaddress import ip_address, IPv6Network
from urllib.parse import urlparse

from pymerang import nat_utils
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

def send_ping(dst_ip):
    # Returns delay in seconds
    delay = ping(dst_ip)
    return delay


def send_keep_alive_udp(dst_ip, dst_port):
    # Create the socket
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        # Send an empty UDP message
        sock.sendto('', (dst_ip, dst_port))


def start_keep_alive_icmp(dst_ip, interval=30, max_lost=0):
    current_lost = 0
    while True:
          # Returns delay in seconds.
        delay = send_ping(dst_ip)
        if max_lost > 0:
            if not delay:
                current_lost += 1
                if current_lost >= max_lost:
                    return
            else:
                current_lost = 0
        time.sleep(interval)


def start_keep_alive_udp(dst_ip, dst_port, interval=30):
    while True:
        send_keep_alive_udp
        time.sleep(interval)


# Allocates private nets
class NetAllocator(object):

  bit = 16
  net = 'fcfa::/%d' % bit
  prefix = 126

  def __init__(self): 
    print('*** Calculating Available Private Nets')
    self.subnets = (IPv6Network(self.net)).subnets(new_prefix=self.prefix)
  
  def nextNet(self):
    net = next(self.subnets)
    return net.__str__()


def parse_ip_port(netloc):
    try:
        ip = ip_address(netloc)
        port = None
    except ValueError:
        parsed = urlparse('//{}'.format(netloc))
        ip = ip_address(parsed.hostname).__str__()
        port = parsed.port
    return ip, port


class TunnelState:

    def __init__(self):
        self.tunnel_modes = dict()
        self.nat_to_tunnel_modes = dict()
        for nat_type in nat_utils.NAT_TYPES:
            self.nat_to_tunnel_modes[nat_type] = dict()
        # Initialize network allocator
        self.net_allocator = NetAllocator()
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
            'vxlan', 5, self.net_allocator)
        )
        self.register_tunnel_mode(
            etherws_utils.TunnelEtherWs('etherws', 10, self.net_allocator)
        )
