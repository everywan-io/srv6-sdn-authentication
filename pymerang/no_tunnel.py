#!/usr/bin/env python

from pymerang import nat_utils
from pymerang import tunnel_utils

class NoTunnel(tunnel_utils.TunnelMode):

    def __init__(self, name, priority, net_allocator=None):
        require_keep_alive_messages = False
        #supported_nat_types = [nat_utils.NAT_TYPE['OpenInternet']]
        supported_nat_types = ['OpenInternet']
        # Create tunnel mode
        super().__init__(name, require_keep_alive_messages,
                         supported_nat_types, priority, net_allocator)

    def create_tunnel_device_endpoint(self, tunnel_info):
    	pass

    def create_tunnel_controller_endpoint(self, tunnel_info):
    	return tunnel_info

    def destroy_tunnel_device_endpoint(self, tunnel_info):
    	pass

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
    	pass
