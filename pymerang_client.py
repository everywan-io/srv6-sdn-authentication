#!/usr/bin/env python

from __future__ import print_function
from ping3 import ping, verbose_ping
import logging
import grpc

import utils
import nat_utils

import pymerang_pb2
import pymerang_pb2_grpc
import status_codes_pb2

# Device ID
DEVICE_ID = 0
# Features supported by the device
FEATURES = [
    {'name': 'gRPC', 'port': 12345},
    {'name': 'SSH', 'port': 22}
]
# Loopback IP address of the controller
CONTROLLER_IP = '::1'
# Port of the gRPC server executing on the controller
CONTROLLER_GRPC_PORT = 50051
# Loopback IP address of the device
DEVICE_IP = 'fcff:1::1'
# Configuration of STUN server/client
STUN_SOURCE_IP = DEVICE_IP
STUN_SOURCE_PORT = 50031
STUN_SERVER_HOST = CONTROLLER_IP
STUN_SERVER_PORT = 3478
# Souce IP address of the NAT discovery
NAT_DISCOVERY_SOURCE_IP = DEVICE_IP
# Source port of the NAT discovery
NAT_DISCOVERY_SOURCE_PORT = 4789
# IP address of the NAT discovery
NAT_DISCOVERY_SERVER_HOST = '::1'
# Port number of the NAT discovery
NAT_DISCOVERY_SERVER_PORT = 50071


class PymerangDevice:

    def __init__(self, device_id, features):
        self.device_id = device_id
        self.nat_type = None
        self.external_ip = None
        self.external_port = None
        self.tunnel_mode = None
        self.features = features

    def process_configuration(self, configuration):
        pass

    def register_device(self, stub):
        # Prepare the registration message
        request = pymerang_pb2.RegisterDeviceRequest()
        request.device.id = self.device_id
        for feature in self.features:
            f = request.device.features.add()
            f.name = feature['name']
            if feature.get('port') is not None:
                f.port = feature['port']
        tunnel_info = request.tunnel_info
        #tunnel_info.tunnel_mode = nat_utils.NAT_TYPES[self.nat_type]
        tunnel_info.tunnel_mode = utils.TUNNEL_MODES[self.tunnel_mode.name]
        tunnel_info.device_id = self.device_id
        if self.external_ip is not None:
            tunnel_info.device_external_ip = self.external_ip
            tunnel_info.device_external_port = self.external_port
        # Send the registration request
        response = stub.RegisterDevice(request)
        if response.status == status_codes_pb2.STATUS_OK:
            # Device authenticated
            configuration = response.device_configuration
            tunnel_info = response.tunnel_info
            logging.info('Device authenticated')
            logging.info('Configuration received: %s' % configuration)
            # Process the configuration received
            self.process_configuration(configuration)
            # Create the tunnel
            self.tunnel_mode.create_tunnel_device_endpoint(tunnel_info)
            # Send a keep-alive messages to keep the tunnel opened, if required
            if self.tunnel_mode.require_keep_alive_messages:
                Thread(target=utils.send_keep_alive_udp, daemon=True)
            # Return the configuration
            return configuration
        elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
            # Authentication failed
            logging.warning('Authentication failed')
            return
        else:
            # Unknown status code
            logging.warning('Unknown status code: %s' % response.status)
            return

    def unregister_device(self, device_id):
        # Get tunnel info
        tunnel_info = self.tunnel_info
        # Destroy the tunnel
        self.tunnel_mode.destroy_tunnel_device_endpoing(tunnel_info)

    def run(self):
        # Initialize tunnel state
        tunnel_state = utils.TunnelState()
        # Run the stun test to discover the NAT type
        #nat_type, external_ip, external_port = nat_utils.run_stun(STUN_SOURCE_IP,
        #                                                          STUN_SOURCE_PORT,
        #                                                          STUN_SERVER_HOST,
        #                                                          STUN_SERVER_PORT)
        nat_type, external_ip, external_port = nat_utils.run_nat_discovery_client(
            NAT_DISCOVERY_SOURCE_IP, NAT_DISCOVERY_SOURCE_PORT,
            NAT_DISCOVERY_SERVER_HOST, NAT_DISCOVERY_SERVER_PORT
        )
        self.nat_type = nat_type
        self.external_ip = external_ip
        self.external_port = external_port
        logging.info('Client started')
        if nat_type is None:
            logging.error('Error in STUN client')
        #logging.info('NAT detected: %s' % nat_utils.NAT_DESC[nat_type])
        logging.info('NAT detected: %s' % nat_type)
        # Get the best tunnel mode working with the NAT type
        self.tunnel_mode = tunnel_state.select_tunnel_mode(nat_type)
        logging.info('Tunnel mode selected: %s' % self.tunnel_mode.name)
        # Establish a gRPC connection to the controller
        server_address = '[%s]:%s' % (CONTROLLER_IP, CONTROLLER_GRPC_PORT)
        with grpc.insecure_channel(server_address) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            logging.info("-------------- GetConfiguration --------------")
            # Start registration procedure
            self.register_device(stub)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    client = PymerangDevice(DEVICE_ID, FEATURES)
    client.run()
