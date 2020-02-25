#!/usr/bin/env python

# General imports
import logging
import pynat
# pymerang imports
from pymerang import tunnel_utils
from pymerang import status_codes_pb2


class NoTunnel(tunnel_utils.TunnelMode):

    ''' Direct communication (no tunnel) '''

    def __init__(self, name, priority, controller_ip=None, debug=False):
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        # Keep alive not required if we use direct communication
        # (i.e. no tunnel)
        req_keep_alive_messages = True
        # NAT types supported by the VXLAN tunnel mode
        supported_nat_types = [
            pynat.OPEN
        ]
        # Create the tunnel mode
        super().__init__(name=name,
                         require_keep_alive_messages=req_keep_alive_messages,
                         supported_nat_types=supported_nat_types,
                         priority=priority,
                         controller_ip=controller_ip,
                         debug=debug)

    def create_tunnel_device_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def create_tunnel_device_endpoint_end(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def create_tunnel_controller_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def update_tunnel_device_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def update_tunnel_device_endpoint_end(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def update_tunnel_controller_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        return status_codes_pb2.STATUS_SUCCESS
