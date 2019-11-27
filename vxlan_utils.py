#!/usr/bin/env python

from ipaddress import IPv6Interface, IPv6Network
from pyroute2 import IPRoute

import tunnel_utils
import nat_utils

VXLAN_DSTPORT = 4789
ENABLE_UDP_CSUM = False
#VXLAN_SRCPORT_MIN = 49152
#VXLAN_SRCPORT_MAX = 65535

def create_vxlan(device, vni, phys_dev, remote, local, remote6, local6, ttl, tos,
                 flowlabel, dstport, srcport_min, srcport_max, learning, proxy,
                 rsc, l2miss, l3miss, udpcsum, udp6zerocsumtx, udp6zerocsumrx,
                 ageing, gbp, gpe):
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
                  vxlan_link=ip.link_lookup(ifname=phys_dev)[0],
                  vxlan_group=remote,
                  vxlan_local=local,
                  vxlan_group6=remote6,
                  vxlan_local6=local6,
                  vxlan_ttl=ttl,
                  vxlan_tos=tos,
                  vxlan_label=flowlabel,
                  vxlan_port=dstport,
                  vxlan_port_range=srcport,
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


class TunnelVXLAN(tunnel_utils.TunnelMode):

    def __init__(self, name, priority, net_allocator):
        require_keep_alive_messages = True
        '''
        supported_nat_types = [nat_utils.NAT_TYPE['OpenInternet'],
                               nat_utils.NAT_TYPE['FullCone'],
                               nat_utils.NAT_TYPE['RestricNAT'],
                               nat_utils.NAT_TYPE['RestricPortNAT'],
                               nat_utils.NAT_TYPE['SymmetricNAT']]
        '''
        supported_nat_types = ['OpenInternet', 'NAT']
        # Create tunnel mode
        super().__init__(name, require_keep_alive_messages,
                         supported_nat_types, priority, net_allocator)

    def create_tunnel_device_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Extract the VTEP IPs and ports
        controller_vtep_ip = tunnel_info.controller_vtep_ip
        device_vtep_ip = tunnel_info.device_vtep_ip
        vtep_mask = tunnel_info.vtep_mask
        # Create the VXLAN interface
        create_vxlan(device='%s-%s' % (self.name, device_id), vni=device_id,
                     remote=controller_ip, local=device_ip,
                     dstport=VXLAN_DSTPORT, srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM)
        # Bring the interface UP
        enable_interface(device='%s-%s' % (self.name, device_id))
        # Add a private address to the interface
        add_address(device='%s-%s' % (self.name, device_id), address=device_vtep_ip,
                    mask=vtep_mask)

    def create_tunnel_controller_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # External IP and port of the device
        device_external_ip = tunnel_info.device_external_ip
        device_external_port = tunnel_info.device_external_port
        # Generate private addresses for the device and controller VTEPs
        net = self.net_allocator.nextNet()   # Change to make dependant from the device ID?
        net = IPv6Network(net)
        controller_vtep_ip = net[0].__str__()
        device_vtep_ip = net[1].__str__()
        vtep_mask = net.prefixlen
        # Create the VXLAN interface
        create_vxlan(device='%s-%s' % (self.name, device_id), vni=device_id,
                     remote=device_received_ip, local=controller_ip,
                     dstport=device_received_port, srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM)
        # Bring the interface UP
        enable_interface(device='%s-%s' % (self.name, device_id))
        # Add a private address to the interface
        add_address(device='%s-%s' % (self.name, device_id), address=controller_vtep_ip,
                    mask=vtep_mask)
        # Update and return the tunnel info
        tunnel_info.controller_vtep_ip = controller_vtep_ip
        tunnel_info.device_vtep_ip = device_vtep_ip
        tunnel_info.vtep_mask = vtep_mask
        return tunnel_info

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        # Delete the VXLAN interface
        delete_interface(device='%s-%s' (self.name, device_id))

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Delete the VXLAN interface
        delete_interface(device='%s-%s' (self.name, device_id))
