#!/usr/bin/env python

from ipaddress import IPv6Interface, IPv6Network
from pyroute2 import IPRoute
from pymerang import etherws

from pymerang import tunnel_utils
from pymerang import nat_utils


class Args:
    pass


class SwArgs(Args):
    debug = False
    logconf = None
    foreground = False
    ageout = 300
    path = '/'
    host = ''
    port = None
    htpasswd = None
    sslkey = None
    sslcert = None
    ctlpath = '/ctl'
    ctlhost = '127.0.0.1'
    ctlport = 7867
    ctlhtpasswd = None
    ctlsslkey = None
    ctlsslkey = None


class CtlArgs(Args):
    ctlurl = 'http://127.0.0.1:7867/ctl'
    ctluser = None
    ctlpasswd = None
    ctlsslcert = None
    ctlinsecure = False


class CtlAddPortArgs(CtlArgs):
    control_method = 'addport'


class CtlAddPortNetDevArgs(CtlAddPortArgs):
    iftype = etherws.NetdevHandler.IFTYPE
    target = None


class CtlAddPortTapArgs(CtlAddPortArgs):
    iftype = etherws.TapHandler.IFTYPE
    target = None


class CtlAddPortClientArgs(CtlAddPortArgs):
    iftype = etherws.ClientHandler.IFTYPE
    target = None
    user = None
    passwd = None
    cacerts = None
    insecure = False


class CtlSetPortArgs(CtlArgs):
    control_method = 'setport'
    port = None
    shut = None


class CtlDelPortArgs(CtlArgs):
    control_method = 'delport'
    port = None


class CtlListPortArgs(CtlArgs):
    control_method = 'listport'


class CtlSetIfArgs(CtlArgs):
    control_method = 'setif'
    port = None
    address = None
    netmask = None
    mtu = None

class CtlListIfPortArgs(CtlArgs):
    control_method = 'listif'


class CtlListFdbPortArgs(CtlArgs):
    control_method = 'listfdb'

def start_etherws():
    sw_args = SwArgs()
    etherws._start_sw(sw_args)


def create_etherws_tap(device):
    ctl_addport_tap_args = CtlAddPortTapArgs()
    ctl_addport_tap_args.target = device
    etherws._start_ctl(ctl_addport_tap_args)


def del_etherws_port(portnum):
    ctl_delport_args = CtlDelPortArgs()
    ctl_delport_args.port = portnum
    etherws._start_ctl(ctl_delport_args)


def create_etherws_websocket(device, addr):
    ctl_addport_client_args = CtlAddPortTapArgs()
    ctl_addport_client_args.target = 'ws://[%s]' % addr
    etherws._start_ctl(ctl_addport_client_args)


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


class TunnelEtherWs(tunnel_utils.TunnelMode):

    def __init__(self, name, priority, net_allocator):
        require_keep_alive_messages = False
        '''
        supported_nat_types = [nat_utils.NAT_TYPE['Blocked'],
                               nat_utils.NAT_TYPE['OpenInternet'],
                               nat_utils.NAT_TYPE['FullCone'],
                               nat_utils.NAT_TYPE['SymmetricUDPFirewall'],
                               nat_utils.NAT_TYPE['RestricNAT'],
                               nat_utils.NAT_TYPE['RestricPortNAT'],
                               nat_utils.NAT_TYPE['SymmetricNAT']]
        '''
        supported_nat_types = ['OpenInternet', 'NAT', 'Blocked']
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
        # Create the EtherWs TAP interface
        create_etherws_tap(device='%s-%s' % (self.name, device_id))
        # Add the private address
        add_address(device='%s-%s' % (self.name, device_id),
                    address=device_vtep_ip, mask=vtep_mask)
        # Create the EtherWs websocket interface
        create_etherws_websocket(device=controller_ip)

    def create_tunnel_controller_endpoint(self, tunnel_info):
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Generate private addresses for the device and controller VTEPs
        net = self.net_allocator.nextNet()   # Change to make dependant from the device ID?
        net = IPv6Network(net)
        controller_vtep_ip = net[0].__str__()
        device_vtep_ip = net[1].__str__()
        vtep_mask = net.prefixlen
        # Create the EtherWs TAP interface
        create_etherws_tap(device='%s-%s' % (self.name, device_id))
        # Add the private address
        add_address(device='%s-%s' % (self.name, device_id),
                    address=device_vtep_ip, mask=vtep_mask)
        # Update and return the tunnel info
        tunnel_info.controller_vtep_ip
        tunnel_info.device_vtep_ip = device_vtep_ip
        tunnel_info.vtep_mask
        return tunnel_info

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        # Delete the TAP interface
        del_etherws_port(1)                     # TODO use pyroute instead?
        # Delete the websocket interface
        del_etherws_port(2)

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        # Delete the TAP interface
        del_etherws_port(1)
