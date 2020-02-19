#!/usr/bin/env python

# General imports
from __future__ import print_function
import logging
from argparse import ArgumentParser
import pynat
import grpc
import json
from threading import Thread
from socket import AF_INET6, AF_INET
# ipaddress dependencies
from ipaddress import IPv4Address, IPv6Address
# pymerang dependencies
from pymerang import utils
from pymerang import pymerang_pb2
from pymerang import pymerang_pb2_grpc
from pymerang import status_codes_pb2


DEFAULT_PYMERANG_SERVER_IP = '2000::1'
# Port of the gRPC server executing on the controller
DEFAULT_PYMERANG_SERVER_PORT = 50061
# Loopback IP address of the device
DEFAULT_PYMERANG_CLIENT_IP = 'fcff:1::1'
# Souce IP address of the NAT discovery
DEFAULT_NAT_DISCOVERY_CLIENT_IP = '0.0.0.0'
# Source port of the NAT discovery
DEFAULT_NAT_DISCOVERY_CLIENT_PORT = 0
# IP address of the NAT discovery
DEFAULT_NAT_DISCOVERY_SERVER_IP = '2000::1'
# Port number of the NAT discovery
DEFAULT_NAT_DISCOVERY_SERVER_PORT = 3478
# Config file
DEFAULT_CONFIG_FILE = '/tmp/config.json'
# Default interval between two keep alive messages
DEFAULT_KEEP_ALIVE_INTERVAL = 30
# Source port of the NAT discovery
DEFAULT_VXLAN_PORT = 4789
# File containing the token
DEFAULT_TOKEN_FILE = 'token'


class PymerangDevice:

    def __init__(self, server_ip, server_port, nat_discovery_server_ip,
                 nat_discovery_server_port, nat_discovery_client_ip,
                 nat_discovery_client_port, config_file,
                 token_file, keep_alive_interval=30, debug=False):
        # Debug mode
        self.debug = debug
        # IP address of the gRPC server
        self.server_ip = server_ip
        # Port on which the gRPC server is listening
        self.server_port = server_port
        # IP address of the NAT discovery server
        self.nat_discovery_server_ip = nat_discovery_server_ip
        # Port of the NAT discovery server
        self.nat_discovery_server_port = nat_discovery_server_port
        # IP address used by the NAT discovery client
        self.nat_discovery_client_ip = nat_discovery_client_ip
        # Port used by the NAT discovery client
        self.nat_discovery_client_port = nat_discovery_client_port
        # NAT type
        self.nat_type = None
        # Device external IP address
        self.external_ip = None
        # Device external port
        self.external_port = None
        # Tunnel mode used by the device
        self.tunnel_mode = None
        # Read configuration file
        with open(config_file, 'r') as json_file:
            config = json.load(json_file)
        # Save the device ID
        self.device_id = config['id']
        # Save the list of the supported features
        self.features = config['features']
        # Save interval between two consecutive keep alive messages
        self.keep_alive_interval = keep_alive_interval
        # VXLAN enforced port
        self.enforced_vxlan_port = None
        # Read the token from the token file
        with open(token_file, 'r') as token_file:
            # Save the token
            self.token = token_file.read()
            # Remove trailing new line character
            self.token = self.token.rstrip('\n')
        # Tunnel state
        self.tunnel_state = None

    def register_device(self):
        # Establish a gRPC connection to the controller
        if utils.getAddressFamily(self.server_ip) == AF_INET6:
            server_address = '[%s]:%s' % (self.server_ip, self.server_port)
        elif utils.getAddressFamily(self.server_ip) == AF_INET:
            server_address = '%s:%s' % (self.server_ip, self.server_port)
        else:
            logging.critical('Invalid address %s' % self.server_ip)
            return
        with grpc.insecure_channel(server_address) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            # Start registration procedure
            logging.info("-------------- RegisterDevice --------------")
            # Prepare the registration message
            request = pymerang_pb2.RegisterDeviceRequest()
            # Set the device ID
            request.device.id = self.device_id
            # Set the token
            request.auth_data.token = self.token
            # Set the features list
            for feature in self.features:
                f = request.device.features.add()
                f.name = feature['name']
                if feature.get('port') is not None:
                    f.port = feature['port']
            # Set the interfaces
            interfaces = utils.get_local_interfaces()
            for ifname, ifinfo in interfaces.items():
                interface = request.interfaces.add()
                interface.name = ifname
                interface.mac_addr = ifinfo['mac_addr']
                interface.ipv6_addrs.extend(ifinfo['ipv6_addrs'])
                interface.ipv4_addrs.extend(ifinfo['ipv4_addrs'])
            # Send the registration request
            logging.info('Sending the registration request')
            response = stub.RegisterDevice(request)
            if response.status == status_codes_pb2.STATUS_SUCCESS:
                logging.info('Device authenticated')
                if self.nat_discovery_client_port == 0:
                    if response.vxlan_port is not None:
                        self.nat_discovery_client_port = response.vxlan_port
                        self.vxlan_port = response.vxlan_port
                    else:
                        self.nat_discovery_client_port = DEFAULT_VXLAN_PORT
                        self.vxlan_port = DEFAULT_VXLAN_PORT
                self.vxlan_port = self.nat_discovery_client_port
                # Return the configuration
                return status_codes_pb2.STATUS_SUCCESS
            elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
                # Authentication failed
                logging.warning('Authentication failed')
                return status_codes_pb2.STATUS_UNAUTHORIZED
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return response.status

    def update_tunnel_mode(self):
        # Establish a gRPC connection to the controller
        if utils.getAddressFamily(self.server_ip) == AF_INET6:
            server_address = '[%s]:%s' % (self.server_ip, self.server_port)
        elif utils.getAddressFamily(self.server_ip) == AF_INET:
            server_address = '%s:%s' % (self.server_ip, self.server_port)
        else:
            logging.critical('Invalid address %s' % self.server_ip)
            return
        with grpc.insecure_channel(server_address) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            # Prepare the registration message
            request = pymerang_pb2.RegisterDeviceRequest()
            # Set the device ID in the tunnel info
            tunnel_info = request.tunnel_info
            tunnel_info.device_id = self.device_id
            # Start registration procedure
            logging.info("-------------- Update Tunnel Mode --------------")
            if self.tunnel_mode is not None:
                # Destroy the tunnel
                logging.info('Destroying the tunnel for the device')
                self.tunnel_mode.destroy_tunnel_device_endpoint(
                    tunnel_info=tunnel_info)
                self.tunnel_mode = None
            # Run the stun test to discover the NAT type
            logging.info('Running STUN test to discover the NAT type\n'
                         'STUN client IP: %s\nSTUN client PORT: %s\n'
                         'STUN server IP: %s\nSTUN server port: %s\n'
                         % (self.nat_discovery_client_ip,
                            self.nat_discovery_client_port,
                            self.nat_discovery_server_ip,
                            self.nat_discovery_server_port))
            nat_type, external_ip, external_port = pynat.get_ip_info(
                self.nat_discovery_client_ip,
                self.nat_discovery_client_port,
                self.nat_discovery_server_ip,
                self.nat_discovery_server_port
            )
            if nat_type is None:
                logging.error('Error in STUN client')
            logging.info('NAT detected: %s' % nat_type)
            # Check if the tunnel mode has changed
            tunnel_mode_changed = True
            if self.nat_type is not None and self.nat_type == nat_type:
                tunnel_mode_changed = False
            # Save the NAT type
            self.nat_type = nat_type
            # Save the external IP address
            self.external_ip = external_ip
            # Save the external port
            self.external_port = external_port
            # Get the best tunnel mode working with the NAT type
            tunnel_mode = self.tunnel_state.select_tunnel_mode(nat_type)
            if tunnel_mode is None:
                logging.error('No tunnel mode supporting the NAT type')
                return
            logging.info('Tunnel mode selected: %s' % tunnel_mode.name)
            # Set the device ID
            request.device.id = self.device_id
            # Set the interfaces
            interfaces = utils.get_local_interfaces()
            for ifname, ifinfo in interfaces.items():
                interface = request.interfaces.add()
                interface.name = ifname
                # interface.ext_ipv6_addrs.extend(ifinfo['ipv6_addrs'])
                # interface.ext_ipv4_addrs.extend(ifinfo['ipv4_addrs'])
                if ifname != 'lo':
                    for addr in ifinfo['ipv4_addrs']:
                        # Run the stun test to discover the
                        # external IP and port of the interface
                        addr = addr.split('/')[0]
                        if not IPv4Address(addr).is_link_local:
                            try:
                                nat_type, external_ip, external_port = \
                                    pynat.get_ip_info(addr.split('/')[0],
                                                      self.nat_discovery_client_port,
                                                      self.nat_discovery_server_ip,
                                                      self.nat_discovery_server_port
                                                      )
                                if external_ip is not None:
                                    interface.ext_ipv4_addrs.append(
                                        external_ip)
                            except OSError as e:
                                logging.warning('Error running STUN test with the '
                                                'following parameters\n'
                                                'STUN client IP: %s\n'
                                                'STUN client PORT: %s\n'
                                                'STUN server IP: %s\n'
                                                'STUN server port: %s\n'
                                                'Error: %s\n\n'
                                                % (addr.split('/')[0],
                                                   self.nat_discovery_client_port,
                                                   self.nat_discovery_server_ip,
                                                   self.nat_discovery_server_port,
                                                   e))
                    for addr in ifinfo['ipv6_addrs']:
                        # Run the stun test to discover the
                        # external IP and port of the interface
                        addr = addr.split('/')[0]
                        if not IPv6Address(addr).is_link_local:
                            try:
                                nat_type, external_ip, external_port = \
                                    pynat.get_ip_info(addr.split('/')[0],
                                                      self.nat_discovery_client_port,
                                                      self.nat_discovery_server_ip,
                                                      self.nat_discovery_server_port
                                                      )
                                if external_ip is not None:
                                    interface.ext_ipv6_addrs.append(
                                        external_ip)
                            except OSError as e:
                                logging.warning('Error running STUN test with the '
                                                'following parameters\n'
                                                'STUN client IP: %s\n'
                                                'STUN client PORT: %s\n'
                                                'STUN server IP: %s\n'
                                                'STUN server port: %s\n'
                                                'Error: %s\n\n'
                                                % (addr.split('/')[0],
                                                   self.nat_discovery_client_port,
                                                   self.nat_discovery_server_ip,
                                                   self.nat_discovery_server_port,
                                                   e))
            # Set the tunnel mode
            self.tunnel_mode = tunnel_mode
            # Set the tunnel mode
            request.tunnel_mode = self.tunnel_mode.name
            # Set the NAT type
            request.nat_type = self.nat_type
            # Set the tunnel info
            tunnel_info = request.tunnel_info
            tunnel_info.tunnel_mode = utils.TUNNEL_MODES[tunnel_mode.name]
            tunnel_info.device_id = self.device_id
            if self.external_ip is not None:
                tunnel_info.device_external_ip = self.external_ip
                tunnel_info.device_external_port = self.external_port
                tunnel_info.vxlan_port = self.vxlan_port
            # Create the tunnel
            logging.info('Creating the tunnel for the device')
            self.tunnel_mode.create_tunnel_device_endpoint(tunnel_info)
            # Send the registration request
            logging.info('Sending the registration request')
            response = stub.UpdateTunnelMode(request)
            if response.status == status_codes_pb2.STATUS_SUCCESS:
                # Tunnel mode established
                tunnel_info = response.tunnel_info
                # Create the tunnel
                logging.info('Finalizing tunnel configuration')
                if tunnel_mode_changed:
                    self.tunnel_mode.create_tunnel_device_endpoint_end(
                        tunnel_info)
                else:
                    self.tunnel_mode.update_tunnel_device_endpoint_end(
                        tunnel_info)
                # Get the controller address
                self.controller_mgmtip = \
                    self.tunnel_mode.get_controller_mgmtip()
                if self.controller_mgmtip is None:
                    self.controller_mgmtip = self.server_ip
                # Send a keep-alive messages to keep the tunnel opened,
                # if required
                if self.tunnel_mode.require_keep_alive_messages:
                    Thread(target=utils.start_keep_alive_icmp,
                           args=(self.controller_mgmtip,
                                 self.keep_alive_interval,
                                 3, self.update_tunnel_mode
                                 ),
                           daemon=False
                           ).start()
                # Return the configuration
                return status_codes_pb2.STATUS_SUCCESS
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return

    def run(self):
        logging.info('Client started')
        # Initialize tunnel state
        self.tunnel_state = utils.TunnelState(self.server_ip, self.debug)
        # Register the device
        if self.register_device() != status_codes_pb2.STATUS_SUCCESS:
            logging.warning('Error in device registration')
            return
        # Update tunnel mode
        if self.update_tunnel_mode() != \
                status_codes_pb2.STATUS_SUCCESS:
            logging.warning('Error in update tunnel mode')
            return


# Parse options
def parse_arguments():
    # Get parser
    parser = ArgumentParser(
        description='pymerang client'
    )
    # Debug mode
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Activate debug logs'
    )
    # Secure mode
    parser.add_argument(
        '-s', '--secure', action='store_true', help='Activate secure mode'
    )
    # IP address of the gRPC server
    parser.add_argument(
        '-i', '--server-ip', dest='server_ip',
        default=DEFAULT_PYMERANG_SERVER_IP, help='Server IP address'
    )
    # Port of the gRPC server
    parser.add_argument(
        '-p', '--server-port', dest='server_port',
        default=DEFAULT_PYMERANG_SERVER_PORT, help='Server port'
    )
    # IP address of the NAT discovery server
    parser.add_argument(
        '-n', '--nat-discovery-server-ip', dest='nat_discovery_server_ip',
        default=DEFAULT_NAT_DISCOVERY_SERVER_IP, help='NAT discovery server IP'
    )
    # Port of the NAT discovery server
    parser.add_argument(
        '-m', '--nat-discovery-server-port', type=int,
        dest='nat_discovery_server_port',
        default=DEFAULT_NAT_DISCOVERY_SERVER_PORT,
        help='NAT discovery server port'
    )
    # IP address used by the NAT discoery client
    parser.add_argument(
        '-l', '--nat-discovery-client-ip', dest='nat_discovery_client_ip',
        default=DEFAULT_NAT_DISCOVERY_CLIENT_IP, help='NAT discovery client IP'
    )
    # Port used by the NAT discovery client
    parser.add_argument(
        '-o', '--nat-discovery-client-port', type=int,
        dest='nat_discovery_client_port',
        default=DEFAULT_NAT_DISCOVERY_CLIENT_PORT,
        help='NAT discovery client port'
    )
    # File containing the configuration of the device
    parser.add_argument(
        '-c', '--config-file', dest='config_file',
        default=DEFAULT_CONFIG_FILE, help='Config file'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-k', '--keep-alive-interval', dest='keep_alive_interval',
        default=DEFAULT_KEEP_ALIVE_INTERVAL,
        help='Interval between two consecutive keep alive'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-t', '--token-file', dest='token_file',
        default=DEFAULT_TOKEN_FILE,
        help='File containing the token used for the authentication'
    )
    # Parse input parameters
    args = parser.parse_args()
    # Return the arguments
    return args


if __name__ == '__main__':
    args = parse_arguments()
    # Setup properly the logger
    debug = args.debug
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(level=logging.INFO)
    # Setup properly the secure mode
    if args.secure:
        secure = True
    else:
        secure = False
    # Server IP
    server_ip = args.server_ip
    # Server port
    server_port = args.server_port
    # NAT discovery server IP
    nat_discovery_server_ip = args.nat_discovery_server_ip
    # NAT discovery server port
    nat_discovery_server_port = args.nat_discovery_server_port
    # NAT discovery client IP
    nat_discovery_client_ip = args.nat_discovery_client_ip
    # NAT discovery client port
    nat_discovery_client_port = args.nat_discovery_client_port
    # Config file
    config_file = args.config_file
    # Interval between two consecutive keep alive messages
    keep_alive_interval = args.keep_alive_interval
    # File containing the token used for the authentication
    token_file = args.token_file
    # Start client
    client = PymerangDevice(server_ip, server_port, nat_discovery_server_ip,
                            nat_discovery_server_port, nat_discovery_client_ip,
                            nat_discovery_client_port, config_file,
                            token_file, keep_alive_interval, debug)
    client.run()
