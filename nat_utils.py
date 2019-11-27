#!/usr/bin/env python

from pystun3 import stun
import socket
import logging

import pymerang_pb2

logging.basicConfig(level=logging.INFO)

'''
NAT_TYPE = {
    'Blocked': 0,
    'OpenInternet': 1,
    'FullCone': 2,
    'SymmetricUDPFirewall': 3,
    'RestricNAT': 4,
    'RestricPortNAT': 5,
    'SymmetricNAT': 6
}

NAT_DESC = {
    'Blocked': 'Blocked',
    'OpenInternet': 'Open Internet',
    'FullCone': 'Full Cone',
    'SymmetricUDPFirewall': 'Symmetric UDP Firewall',
    'RestricNAT': 'Restric NAT',
    'RestricPortNAT': 'Restric Port NAT',
    'SymmetricNAT': 'Symmetric NAT'
}

REVERSE_NAT_DESC = {v: k for k, v in NAT_DESC.items()}
'''

NAT_TYPES = ['Blocked', 'OpenInternet', 'NAT']

# STUN test for IPv4
def run_stun(source_ip, source_port, stun_host, stun_port):
    # Run stun
    nat_type, external_ip, external_port = stun.get_ip_info(
        source_ip=source_ip,
        source_port=source_port,
        stun_host=stun_host,
        stun_port=stun_port
    )
    # Return
    return REVERSE_NAT_DESC.get(nat_type), external_ip, external_port

MAX_FAILED = 5
TIMEOUT = 10
BUF_SIZE = 1024

# NAT discovery for IPv6
def run_nat_discovery_client(source_ip, source_port, server_ip, server_port):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind((source_ip, source_port))
        sock.settimeout(TIMEOUT)
        failed = 0
        while failed <= MAX_FAILED:
            sock.sendto(b'nat_discovery', (server_ip, server_port))
            try:
                while True:
                    data, addr = sock.recvfrom(BUF_SIZE)
                    external_ip, external_port = data.decode().split(',')
                    external_port = int(external_port)
                    if addr[0] == server_ip and addr[1] == server_port:
                        if source_ip == external_ip and source_port == external_port:
                            return 'OpenInternet', external_ip, external_port
                        else:
                            return 'NAT', external_ip, external_port
            except socket.timeout:
                failed += 1
        return 'Blocked', None, None

def run_nat_discovery_server(server_ip, server_port):
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind((server_ip, server_port))
        while True:
            data, external_addr = sock.recvfrom(BUF_SIZE)
            if data.decode() == 'nat_discovery':
                sock.sendto(('%s,%s' % (external_addr[0], external_addr[1])).encode(),
                            external_addr)
            else:
                logging.warning('Received an invalid message: %s' % data)