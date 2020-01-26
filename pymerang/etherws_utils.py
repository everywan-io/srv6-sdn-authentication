#!/usr/bin/env python

# General imports
import logging
import pynat
from socket import AF_INET, AF_INET6
# ipaddress dependencies
from ipaddress import IPv6Network, IPv4Network
# pymerang dependencies
from pymerang import etherws
from pymerang import tunnel_utils
from pymerang import status_codes_pb2


'''
Classes and helper functions used to interact with the etherws library
'''


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


def create_etherws_websocket(addr):
    ctl_addport_client_args = CtlAddPortClientArgs()
    ctl_addport_client_args.target = 'ws://[%s]' % addr
    etherws._start_ctl(ctl_addport_client_args)


class TunnelEtherWs(tunnel_utils.TunnelMode):

    ''' Ethernet over Websocket tunnel mode '''

    def __init__(self, name, priority, controller_ip,
                 ipv6_net_allocator, ipv4_net_allocator, debug=False):
        # etherws tunnel mode requires to exchange keep alive
        # messages to keep the tunnel open
        req_keep_alive_messages = True
        # NAT types supported by the etherws tunnel mode
        supported_nat_types = [
            pynat.OPEN,
            pynat.FULL_CONE,
            pynat.RESTRICTED_CONE,
            pynat.RESTRICTED_PORT,
            pynat.SYMMETRIC,
            pynat.UDP_FIREWALL,
            pynat.BLOCKED,
        ]
        # Create the tunnel mode
        super().__init__(name=name,
                         require_keep_alive_messages=req_keep_alive_messages,
                         supported_nat_types=supported_nat_types,
                         priority=priority,
                         controller_ip=controller_ip,
                         ipv6_net_allocator=ipv6_net_allocator,
                         ipv4_net_allocator=ipv4_net_allocator,
                         ipv6_address_allocator=None,
                         ipv4_address_allocator=None,
                         debug=debug)

    def create_tunnel_device_endpoint(self, tunnel_info):
        # Nothing to do
        return status_codes_pb2.STATUS_SUCCESS

    def create_tunnel_device_endpoint_end(self, tunnel_info):
        logging.info('Configuring the etherws tunnel')
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Extract the VTEP IPs
        controller_vtep_ip = tunnel_info.controller_vtep_ip
        device_vtep_ip = tunnel_info.device_vtep_ip
        vtep_mask = tunnel_info.vtep_mask
        # Name of the TAP interface
        tap_name = '%s-%s' % (self.name, device_id[:3])
        # Create the etherws TAP interface
        logging.debug('Attempting to create the TAP '
                      'interface %s' % tap_name)
        create_etherws_tap(device=tap_name)
        # Add the private address
        logging.debug('Attempting to assign the IP address %s/%s '
                      'to the TAP management interface %s'
                      % (device_vtep_ip, vtep_mask, tap_name))
        tunnel_utils.add_address(device=tap_name,
                                 address=device_vtep_ip, mask=vtep_mask)
        # Create the etherws websocket interface
        logging.debug('Attempting to create the websocket '
                      'interface with dst address %s' % self.controller_ip)
        create_etherws_websocket(addr=self.controller_ip)
        # Save the VTEP's IP address of the controller
        self.controller_mgmtip = controller_vtep_ip
        # Success
        logging.debug('The etherws tunnel has been configured')
        return status_codes_pb2.STATUS_SUCCESS

    def create_tunnel_controller_endpoint(self, tunnel_info):
        logging.info('Configuring the etherws tunnel for the device %s'
                     % tunnel_info.device_id)
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Generate private addresses for the device and controller VTEPs
        family = tunnel_utils.getAddressFamily(tunnel_info.device_external_ip)
        if family == AF_INET6:
            # Change to make dependant from the device ID?
            net = self.get_new_mgmt_ipv6_net(device_id)
            net = IPv6Network(net)
            controller_vtep_ip = net[1].__str__()
            device_vtep_ip = net[2].__str__()
            vtep_mask = net.prefixlen
        #elif family == AF_INET:       # TODO handle IPv6
        else:
            net = self.get_new_mgmt_ipv4_net(device_id)
            net = IPv4Network(net)
            controller_vtep_ip = net[1].__str__()
            device_vtep_ip = net[2].__str__()
            vtep_mask = net.prefixlen
        #else:
        #    logging.error('Invalid family address: %s' %
        #                  tunnel_info.device_external_ip)
        #    return status_codes_pb2.STATUS_INTERNAL_ERROR
        # Name of the TAP interface
        tap_name = '%s-%s' % (self.name, device_id[:3])
        # Create the etherws TAP interface
        logging.debug('Attempting to create the TAP '
                      'interface %s' % tap_name)
        create_etherws_tap(device=tap_name)
        # Add the private address
        logging.debug('Attempting to assign the IP address %s/%s '
                      'to the TAP management interface %s'
                      % (controller_vtep_ip, vtep_mask, tap_name))
        tunnel_utils.add_address(device=tap_name,
                                 address=controller_vtep_ip, mask=vtep_mask)
        # Update and return the tunnel info
        tunnel_info.controller_vtep_ip = controller_vtep_ip
        tunnel_info.device_vtep_ip = device_vtep_ip
        tunnel_info.vtep_mask = vtep_mask
        # Success
        logging.debug('The etherws tunnel has been configured')
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        logging.info('Destroying the etherws tunnel')
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Delete the TAP interface
        tap_name = '%s-%s' % (self.name, device_id[:3])
        tunnel_utils.delete_interface(device=tap_name)
        # del_etherws_port(1)
        # Delete the websocket interface
        # del_etherws_port(2)
        # Remove the controller private address
        self.controller_private_ip = None
        # Success
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        logging.info('Destroying the VXLAN tunnel for the device %s'
                     % tunnel_info.device_id)
        # Extract the device ID
        device_id = tunnel_info.device_id
        # Delete the TAP interface
        tap_name = '%s-%s' % (self.name, device_id[:3])
        tunnel_utils.delete_interface(device=tap_name)
        # Delete the TAP interface
        # del_etherws_port(1)
        # Release the private IP address associated to the device
        self.release_ipv4_address(device_id)
        self.release_ipv6_address(device_id)
        # Success
        return status_codes_pb2.STATUS_SUCCESS
