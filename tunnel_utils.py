#!/usr/bin/env python

class TunnelMode:

    def __init__(self, name, require_keep_alive_messages, supported_nat_types,
                 priority, net_allocator):
        self.name = name
        self.require_keep_alive_messages = require_keep_alive_messages
        self.supported_nat_types = supported_nat_types
        self.priority = priority
        self.net_allocator = net_allocator

    def create_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    def create_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError

    def destroy_tunnel_device_endpoint(self, tunnel_info):
        raise NotImplementedError

    def destroy_tunnel_controller_endpoint(self, tunnel_info):
        raise NotImplementedError
