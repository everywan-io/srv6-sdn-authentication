#!/usr/bin/env python

import pynat
from ipaddress import IPv4Network, IPv6Network
from pyroute2 import IPRoute

from pymerang import tunnel_utils

import socket

VXLAN_DSTPORT = 4789
ENABLE_UDP_CSUM = False
#VXLAN_SRCPORT_MIN = 49152
#VXLAN_SRCPORT_MAX = 65535

def create_vxlan(device, vni, phys_dev=None, remote=None,
                 local=None, remote6=None, local6=None,
                 ttl=None, tos=None, flowlabel=None,
                 dstport=None, srcport_min=None,
                 srcport_max=None, learning=None, proxy=None,
                 rsc=None, l2miss=None, l3miss=None,
                 udpcsum=None, udp6zerocsumtx=None,
                 udp6zerocsumrx=None, ageing=None,
                 gbp=None, gpe=None):
    '''
    From the Manpage:

    ip link add DEVICE type vxlan id VNI [ dev PHYS_DEV ] [ { group |
    remote } IPADDR ] [ local { IPADDR | any } ] [ ttl TTL ] [ tos TOS ]
    [ flowlabel FLOWLABEL ] [ dstport PORT ] [ srcport MIN MAX ] [
    [no]learning ] [ [no]proxy ] [ [no]rsc ] [ [no]l2miss ] [ [no]l3miss
    ] [ [no]udpcsum ] [ [no]udp6zerocsumtx ] [ [no]udp6zerocsumrx ] [
    ageing SECONDS ] [ maxaddress NUMBER ] [ [no]external ] [ gbp ] [ gpe
    ]
    '''
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Create the link
    ip_route.link("add",
                  ifname=device,
                  kind="vxlan",
                  vxlan_id=vni,
                  vxlan_link=ip_route.link_lookup(ifname=phys_dev)[0] if phys_dev is not None else None,
                  vxlan_group=remote,           # TODO FIX remote - remote6
                  vxlan_local=local,
                  vxlan_group6=remote6,
                  vxlan_local6=local6,
                  vxlan_ttl=ttl,
                  vxlan_tos=tos,
                  vxlan_label=flowlabel,
                  vxlan_port=dstport,
                  vxlan_port_range={'low': srcport_min, 'high': srcport_max},
                  vxlan_learning=learning,
                  vxlan_proxy=proxy,
                  vxlan_rsc=rsc,
                  vxlan_l2miss=l2miss,
                  vxlan_l3miss=l3miss,
                  vxlan_udp_csum=udpcsum,
                  vxlan_udp_zero_csum6_tx=udp6zerocsumtx,
                  vxlan_udp_zero_csum6_rx=udp6zerocsumrx,
                  vxlan_ageing=ageing,
                  vxlan_gbp=gbp,
                  vxlan_gpe=gpe
    )


def enable_interface(device):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Get interface index
    ifindex = ip_route.link_lookup(ifname=device)[0]
    # Bring link up
    ip_route.link("set", index=ifindex, state="up")


def disable_interface(device):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Get interface index
    ifindex = ip_route.link_lookup(ifname=device)[0]
    # Put link down
    ip_route.link("set", index=ifindex, state="down")


def delete_interface(device):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Get interface index
    ifindex = ip_route.link_lookup(ifname=device)[0]
    # Delete link
    ip_route.link("del", index=ifindex)


def add_address(device, address, mask):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Get interface index
    ifindex = ip_route.link_lookup(ifname=device)[0]
    # Add the address
    ip_route.addr('add', index=ifindex, address=address, mask=mask)


def del_address(device, address, mask):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Get interface index
    ifindex = ip_route.link_lookup(ifname=device)[0]
    # Add the address
    ip_route.addr('del', index=ifindex, address=address, mask=mask)

def add_route(dst, gateway, dev, family):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Create the route
    ip_route.route('add', dst=dst, oif=ip_route.link_lookup(ifname=dev)[0],
                    gateway=gateway, family=family)

def update_fdb(dst, lladdr, dev):
    # Get pyroute2 instance
    ip_route = IPRoute()
    # Replace the entry
    ip_route.fdb('replace',
                 ifindex=ip_route.link_lookup(ifname=dev)[0],
                 lladdr=lladdr,
                 dst=dst)
                

class TunnelVXLAN(tunnel_utils.TunnelMode):

    def __init__(self, name, priority, server_ip, ipv6_net_allocator, ipv4_net_allocator):
        require_keep_alive_messages = True
        '''
        supported_nat_types = [nat_utils.NAT_TYPE['OpenInternet'],
                               nat_utils.NAT_TYPE['FullCone'],
                               nat_utils.NAT_TYPE['RestricNAT'],
                               nat_utils.NAT_TYPE['RestricPortNAT'],
                               nat_utils.NAT_TYPE['SymmetricNAT']]
        '''
        #supported_nat_types = ['OpenInternet', 'NAT']
        supported_nat_types = [
            pynat.OPEN,
            pynat.FULL_CONE,
            pynat.RESTRICTED_CONE,
            pynat.RESTRICTED_PORT
        ]
        # Create tunnel mode
        super().__init__(name, require_keep_alive_messages,
                         supported_nat_types, priority, server_ip, ipv6_net_allocator, ipv4_net_allocator)
        self.last_used_vni = -1
        self.server_ip = server_ip
        self.vni = dict()

    def create_tunnel_device_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Extract the VTEP IPs and ports
        controller_vtep_ip = tunnel_info.controller_vtep_ip
        device_vtep_ip = tunnel_info.device_vtep_ip
        vtep_mask = tunnel_info.vtep_mask
        vni = tunnel_info.vni
        self.vni[device_id] = vni
        # Get device IP
        #host_name = socket.gethostname()
        #device_ip = socket.gethostbyname(host_name)
        #print('host name', host_name)
        #print('device ip', device_ip)



        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        create_vxlan(device=vxlan_name, vni=vni,
                     remote=self.server_ip, #local=device_ip,
                     dstport=VXLAN_DSTPORT, srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM)
        # Bring the interface UP
        enable_interface(device=vxlan_name)
        # Add a private address to the interface
        add_address(device=vxlan_name, address=device_vtep_ip,
                    mask=vtep_mask)
        print('ext ip', self.server_ip)
        print(controller_vtep_ip)
        #self.controller_ip = controller_vtep_ip
        self.controller_ip[device_id] = controller_vtep_ip
        # Route the packets sent to the device through the VTEP
        #add_route(dst=self.server_ip, gateway=controller_vtep_ip,
        #          family=tunnel_utils.getAddressFamily(self.server_ip),
        #          dev=vxlan_name)

    def create_tunnel_controller_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        print('\n\n\nDEV ID', device_id)
        print(tunnel_info)
        # External IP and port of the device
        device_external_ip = tunnel_info.device_external_ip
        device_external_port = tunnel_info.device_external_port
        # VNI
        self.last_used_vni += 1
        vni = self.last_used_vni
        self.vni[device_id] = vni
        # Generate private addresses for the device and controller VTEPs
        if tunnel_utils.getAddressFamily(tunnel_info.device_external_ip) == socket.AF_INET6:
            net = self.ipv6_net_allocator.nextNet()   # Change to make dependant from the device ID?
            net = IPv6Network(net)
            controller_vtep_ip = net[0].__str__()
            device_vtep_ip = net[1].__str__()
            vtep_mask = net.prefixlen
        elif tunnel_utils.getAddressFamily(tunnel_info.device_external_ip) == socket.AF_INET:
            net = self.ipv4_net_allocator.nextNet()   # Change to make dependant from the device ID?
            net = IPv4Network(net)
            controller_vtep_ip = net[1].__str__()
            device_vtep_ip = net[2].__str__()
            vtep_mask = net.prefixlen
        else:
            print('Invalid family address: %s' % tunnel_info.device_external_ip)
            exit(-1)
        self.device_ip[device_id] = device_vtep_ip
        self.controller_ip[device_id] = controller_vtep_ip
        self.vtep_mask[device_id] = vtep_mask
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        create_vxlan(device=vxlan_name, vni=vni,
                     remote=device_external_ip, local=self.server_ip,
                     dstport=device_external_port, srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM)
        # Bring the interface UP
        enable_interface(device=vxlan_name)
        # Add a private address to the interface
        add_address(device=vxlan_name, address=controller_vtep_ip,
                    mask=vtep_mask)
        print('ext ip', device_external_ip)
        print(device_vtep_ip)
        # Route the packets sent to the device through the VTEP
        #add_route(dst=device_external_ip, gateway=device_vtep_ip,
        #          family=tunnel_utils.getAddressFamily(device_external_ip),
        #          dev=vxlan_name)
        # Update and return the tunnel info
        tunnel_info.controller_vtep_ip = controller_vtep_ip
        tunnel_info.device_vtep_ip = device_vtep_ip
        tunnel_info.vtep_mask = vtep_mask
        tunnel_info.vni = vni
        return tunnel_info

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        vni = self.vni[tunnel_info.device_id]
        print('remote vni')
        print(self.name)
        print(vni)
        # Delete the VXLAN interface
        delete_interface(device='%s-%s' % (self.name, vni))

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Delete the VXLAN interface
        delete_interface(device='%s-%s' % (self.name, device_id))       # TODO fix

    def update_tunnel_device_endpoint(self, device_id, tunnel_info):
        pass

    def update_tunnel_controller_endpoint(self, device_id, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # External IP and port of the device
        device_external_ip = tunnel_info.device_external_ip
        device_external_port = tunnel_info.device_external_port
        # VNI
        #self.last_used_vni += 1
        #vni = self.last_used_vni
        vni = self.vni[device_id]
        # Generate private addresses for the device and controller VTEPs
        if tunnel_utils.getAddressFamily(tunnel_info.device_external_ip) == socket.AF_INET6:
            net = self.ipv6_net_allocator.nextNet()   # Change to make dependant from the device ID?
            net = IPv6Network(net)
            controller_vtep_ip = net[0].__str__()
            device_vtep_ip = net[1].__str__()
            vtep_mask = net.prefixlen
        elif tunnel_utils.getAddressFamily(tunnel_info.device_external_ip) == socket.AF_INET:
            net = self.ipv4_net_allocator.nextNet()   # Change to make dependant from the device ID?
            net = IPv4Network(net)
            controller_vtep_ip = net[1].__str__()
            device_vtep_ip = net[2].__str__()
            vtep_mask = net.prefixlen
        else:
            print('Invalid family address: %s' % tunnel_info.device_external_ip)
            exit(-1)
        device_vtep_ip = self.device_ip[device_id]
        controller_vtep_ip = self.controller_ip[device_id]
        vtep_mask = self.vtep_mask[device_id]
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        delete_interface(device=vxlan_name)
        create_vxlan(device=vxlan_name, vni=vni,
                     remote=device_external_ip, local=self.server_ip,
                     dstport=device_external_port, srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM)
        # Bring the interface UP
        enable_interface(device=vxlan_name)
        # Add a private address to the interface
        add_address(device=vxlan_name, address=controller_vtep_ip,
                    mask=vtep_mask)
        # Route the packets sent to the device through the VTEP
        #add_route(dst=device_external_ip, gateway=device_vtep_ip,
        #          family=tunnel_utils.getAddressFamily(device_external_ip),
        #          dev=vxlan_name)
        # Update and return the tunnel info
        tunnel_info.controller_vtep_ip = controller_vtep_ip
        tunnel_info.device_vtep_ip = device_vtep_ip
        tunnel_info.vtep_mask = vtep_mask
        tunnel_info.vni = vni
        return tunnel_info
