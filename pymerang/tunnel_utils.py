#!/usr/bin/env python

# General imports
import logging
import socket
from ipaddress import IPv6Interface, IPv4Interface, AddressValueError


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

    '''
    Class representing a tunnel mode use for controller-device communication
    '''

    def __init__(self, name, require_keep_alive_messages, supported_nat_types,
                 priority, controller_ip, ipv6_address_allocator,
                 ipv4_address_allocator, ipv6_net_allocator,
                 ipv4_net_allocator, debug=False):
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        logging.info('Initiating the tunnel mode:\n'
                     'name=%s\npriority=%s\ncontroller_ip=%s\n'
                     'require_keep_alive_messages=%s\n'
                     'supported_nat_types=%s\n'
                     % (name, priority, controller_ip,
                        require_keep_alive_messages, supported_nat_types))
        # Name used to identify tunnel mode
        self.name = name
        # True if the tunnel mode require keep alive messages
        # sent over the tunnel
        self.require_keep_alive_messages = require_keep_alive_messages
        # NAT types supported by the tunnel mode
        self.supported_nat_types = supported_nat_types
        # Priority index, lower is better
        self.priority = priority
        # Public IP address of the controller
        self.controller_ip = controller_ip
        # Private IPv6 net allocator
        self.ipv6_net_allocator = ipv6_net_allocator
        # Private IPv4 net allocator
        self.ipv4_net_allocator = ipv4_net_allocator
        # Private IPv6 address allocator
        self.ipv6_address_allocator = ipv6_address_allocator
        # Private IPv4 address allocator
        self.ipv4_address_allocator = ipv4_address_allocator
        # Mapping device ID to private IPv4 nets (stored in the controller)
        self.device_to_ipv4_net = dict()
        # Mapping device ID to private IPv6 nets (stored in the controller)
        self.device_to_ipv6_net = dict()
        # Set of reusable IPv4 nets
        self.reusable_ipv4_nets = set()
        # Set of reusable IPv6 nets
        self.reusable_ipv6_nets = set()
        # Mapping device ID to private IPv4 address (stored in the controller)
        self.device_to_ipv4_address = dict()
        # Mapping device ID to private IPv6 address (stored in the controller)
        self.device_to_ipv6_address = dict()
        # Set of reusable IPv4 addresses
        self.reusable_ipv4_addresses = set()
        # Set of reusable IPv6 addresses
        self.reusable_ipv6_addresses = set()
        # Private IPv4 address of the controller (stored in the controller)
        self.controller_private_ipv4 = None
        # Private IPv6 address of the controller (store in the controller)
        self.controller_private_ipv6 = None
        # Private IP address of the controller (stored in the device)
        self.controller_private_ip = None

    # Invoked on the device, before the registration request
    def create_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the device, after the controller reply
    def create_tunnel_device_endpoint_end(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the controller, when the registration request is received
    def create_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the device, when the tunnel has to be destroyed
    def destroy_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the controller, when the tunnel has to be destroyed
    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the device, before the update request
    def update_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the device, after the controller reply
    def update_tunnel_device_endpoint_end(self, tunnel_info):
        raise NotImplementedError

    # Invoked on the controller, when the update request is received
    def update_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    # Return the private IPv6 of the device
    def get_device_private_ipv6(self, tenantid, device_id):
        if tenantid not in self.device_to_ipv6_address:
            return None
        return self.device_to_ipv6_address[tenantid].get(device_id)

    # Return the private IPv4 of the device
    def get_device_private_ipv4(self, tenantid, device_id):
        if tenantid not in self.device_to_ipv4_address:
            return None
        return self.device_to_ipv4_address[tenantid].get(device_id)

    # Return the private IP of the device
    def get_device_private_ip(self, tenantid, device_id):
        addr = self.get_device_private_ipv4(tenantid, device_id)
        if addr is None:
            addr = self.get_device_private_ipv6(tenantid, device_id)
        return addr

    # Return the public IP of the controller
    def get_controller_ip(self):
        return self.controller_ip

    # Return the private IP of the controller
    def get_controller_private_ip(self):
        return self.controller_private_ip

    # Initiate tenant ID
    def init_tenantid(self, tenantid):
        if self.device_to_ipv4_address is not None:
            self.device_to_ipv4_address[tenantid] = dict()
        if self.device_to_ipv6_address is not None:
            self.device_to_ipv6_address[tenantid] = dict()
        if self.device_to_ipv4_net is not None:
            self.device_to_ipv4_net[tenantid] = dict()
        if self.device_to_ipv6_net is not None:
            self.device_to_ipv6_net[tenantid] = dict()

    # Release tenant ID
    def release_tenantid(self, tenantid):
        if self.device_to_ipv4_address:
            del self.device_to_ipv4_address[tenantid]
        if self.device_to_ipv6_address:
            del self.device_to_ipv6_address[tenantid]
        if self.device_to_ipv4_net:
            del self.device_to_ipv4_net[tenantid]
        if self.device_to_ipv6_net:
            del self.device_to_ipv6_net[tenantid]

    # Allocate a new private IPv4 address for the device
    # If the device already has a IPv4 address, return it
    def get_new_ipv4_address(self, device_id, tenantid):
        if device_id in self.device_to_ipv4_address[tenantid]:
            return self.device_to_ipv4_address[tenantid][device_id]
        elif len(self.reusable_ipv4_addresses) > 0:
            addr = self.reusable_ipv4_addresses.pop()
        else:
            addr = '%s/%s' % (self.ipv4_address_allocator.nextAddress(),
                              self.ipv4_address_allocator.prefix)
        self.device_to_ipv4_address[tenantid][device_id] = addr
        return addr

    # Allocate a new private IPv6 address for the device
    # If the device already has a IPv4 address, return it
    def get_new_ipv6_address(self, device_id, tenantid):
        if device_id in self.device_to_ipv6_address[tenantid]:
            return self.device_to_ipv6_address[tenantid][device_id]
        elif len(self.reusable_ipv6_addresses) > 0:
            addr = self.reusable_ipv6_addresses.pop()
        else:
            addr = '%s/%s' % (self.ipv6_address_allocator.nextAddress(),
                              self.ipv6_address_allocator.prefix)
        self.device_to_ipv6_address[tenantid][device_id] = addr
        return addr

    # Release the IPv4 address associated to the device
    def release_ipv4_address(self, device_id, tenantid):
        addr = self.device_to_ipv4_address[tenantid].pop(device_id)
        if addr is not None:
            self.reusable_ipv4_addresses.add(addr)

    # Release the IPv6 address associated to the device
    def release_ipv6_address(self, device_id, tenantid):
        addr = self.device_to_ipv6_address[tenantid].pop(device_id)
        if addr is not None:
            self.reusable_ipv6_addresses.add(addr)

    # Get a new private IPv4 net for the device-controller communication
    # If the device already has a IPv4 net, return it
    def get_new_ipv4_net(self, device_id):
        if device_id in self.device_to_ipv4_net:
            return self.device_to_ipv4_net[device_id]
        elif len(self.reusable_ipv4_nets) > 0:
            net = self.reusable_ipv4_nets.pop()
        else:
            net = self.ipv4_net_allocator.nextNet()
        self.device_to_ipv4_net[device_id] = net
        return net

    # Get a new private IPv6 net for the device-controller communication
    # If the device already has a IPv6 net, return it
    def get_new_ipv6_net(self, device_id):
        if device_id in self.device_to_ipv6_net:
            return self.device_to_ipv6_net[device_id]
        elif len(self.reusable_ipv6_nets) > 0:
            net = self.reusable_ipv6_nets.pop()
        else:
            net = self.ipv6_net_allocator.nextNet()
        self.device_to_ipv6_net[device_id] = net
        return net

    # Release the IPv4 net associated to the device
    def release_ipv4_net(self, device_id):
        net = self.device_to_ipv4_net.pop(device_id)
        if net is not None:
            self.reusable_ipv4_nets.add(net)

    # Release the IPv6 net associated to the device
    def release_ipv6_net(self, device_id):
        net = self.device_to_ipv6_net.pop(device_id)
        if net is not None:
            self.reusable_ipv6_nets.add(net)

    # Get the number of IPv4 addresses allocated for a tenant
    def num_ipv4_addresses(self, tenantid):
        return len(self.device_to_ipv6_address.get(tenantid, set())) + \
            len(self.device_to_ipv4_address.get(tenantid, set()))
