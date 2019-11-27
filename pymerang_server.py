#!/usr/bin/env python

from concurrent import futures
from multiprocessing import Process
from ipaddress import IPv6Network, IPv4Network
import logging
import time
import inspect

import utils
import nat_utils

import grpc

import pymerang_pb2
import pymerang_pb2_grpc
import status_codes_pb2

# Loopback IP address of the controller
CONTROLLER_IP = '::1'
# Port of the gRPC server executing on the controller
CONTROLLER_GRPC_PORT = 50051
# IP address of the NAT discovery
NAT_DISCOVERY_SERVER_HOST = '::1'
# Port number of the NAT discovery
NAT_DISCOVERY_SERVER_PORT = 50071


class PymerangServicer(pymerang_pb2_grpc.PymerangServicer):
    """Provides methods that implement functionality of route guide server."""

    def __init__(self, controller):
        self.controller = controller

    def RegisterDevice(self, request, context):
        # Extract the parameters from the registration request
        logging.debug('New device connected: %s' % request)
        device_id = request.device.id
        features = dict()
        for feature in request.device.features:
            name = feature.name
            port = feature.port
            features[name] = {name: name, port: port}
        auth_data = request.auth_data
        tunnel_info = request.tunnel_info
        # Register the device
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = tunnel_info.device_external_port
        response, tunnel_info = self.controller.register_device(
            device_id, features, auth_data, reply.tunnel_info
        )
        if response is not status_codes_pb2.STATUS_OK:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Generate the configuration for the device
        #config = self.controller.devices[device_id]['device_configuration']
        config = self.controller.configurations[device_id]
        reply.status = status_codes_pb2.STATUS_OK
        #reply.device_configuration =       # TODO
        return reply


class PymerangController:

    def __init__(self, ip='::1', port=50051):
        self.ip = ip
        self.port = port
        self.devices = dict()
        self.configurations = dict()
        self.tunnel_state = None

    def authenticate_device(self, device_id, auth_data):
        return True     # TODO

    def register_device(self, device_id, features, auth_data, tunnel_info):
        # Device authentication
        authenticated = self.authenticate_device(device_id, auth_data)
        if not authenticated:
            return status_codes_pb2.STATUS_UNAUTHORIZED, None
        # Get the tunnel mode required by the device
        tunnel_mode = utils.REVERSE_TUNNEL_MODES[tunnel_info.tunnel_mode]
        tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
        # Create the tunnel
        tunnel_mode.create_tunnel_controller_endpoint(tunnel_info)
        # Register the device
        self.devices[device_id] = dict()
        self.devices[device_id]['features'] = features
        self.devices[device_id]['tunnel_mode'] = tunnel_info.tunnel_mode
        self.devices[device_id]['tunnel_info'] = tunnel_info
        # Return the configuration
        return status_codes_pb2.STATUS_OK, tunnel_info

    def unregister_device(self, device_id):
        # Get the tunnel mode
        tunnel_mode = self.devices[device_id]['tunnel_mode']
        tunnel_info = self.devices[device_id]['tunnel_info']
        # Destroy the tunnel
        tunnel_mode.destroy_tunnel_controller_endpoing(tunnel_info)

    def load_device_config(self):
        #self.devices[0] = dict()
        #self.devices[0]['device_configuration'] = {}
        self.configurations[0] = {}

    def serve(self):
        # Initialize tunnel state
        self.tunnel_state = utils.TunnelState()
        # Start gRPC server
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        pymerang_pb2_grpc.add_PymerangServicer_to_server(
            PymerangServicer(self), server
        )
        server_address = '[%s]:%s' % (CONTROLLER_IP, CONTROLLER_GRPC_PORT)
        logging.info('Server started: listening on %s' % server_address)
        server.add_insecure_port(server_address)
        server.start()
        #server.wait_for_termination()
        while True:
            time.sleep(10)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    p = Process(target=nat_utils.run_nat_discovery_server,
                args=(NAT_DISCOVERY_SERVER_HOST, NAT_DISCOVERY_SERVER_PORT))
    #p.start()
    controller = PymerangController(CONTROLLER_IP, CONTROLLER_GRPC_PORT)
    controller.load_device_config()
    controller.serve()
