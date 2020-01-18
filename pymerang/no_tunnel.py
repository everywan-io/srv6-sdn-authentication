#!/usr/bin/env python

import pynat
from pymerang import tunnel_utils

class NoTunnel(tunnel_utils.TunnelMode):

    def __init__(self, name, priority, server_ip=None, ipv6_net_allocator=None, ipv4_net_allocator=None):
        require_keep_alive_messages = False
        #supported_nat_types = [nat_utils.NAT_TYPE['OpenInternet']]
        supported_nat_types = [
            pynat.OPEN
        ]
        # Create tunnel mode
        super().__init__(name, require_keep_alive_messages,
                         supported_nat_types, priority, server_ip, ipv6_net_allocator, ipv4_net_allocator)

    def create_tunnel_device_endpoint(self, tunnel_info):
    	pass

    def create_tunnel_device_endpoint_end(self, tunnel_info):
    	pass

    def create_tunnel_controller_endpoint(self, tunnel_info):
    	return tunnel_info

    def update_tunnel_device_endpoint(self, tunnel_info):
    	pass

    def update_tunnel_device_endpoint_end(self, tunnel_info):
    	pass

    def update_tunnel_controller_endpoint(self, tunnel_info):
    	return tunnel_info

    def destroy_tunnel_device_endpoint(self, tunnel_info):
    	pass

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
    	pass
