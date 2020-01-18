#!/usr/bin/env python

from __future__ import print_function
from argparse import ArgumentParser
#import stun
import pynat
#from ping3 import ping, verbose_ping
import logging
import grpc
import json
from threading import Thread
from socket import AF_INET6, AF_INET


from pymerang import utils
#from pymerang import nat_utils

from pymerang import pymerang_pb2
from pymerang import pymerang_pb2_grpc
from pymerang import status_codes_pb2

from nat_utils import nat_discovery_client, utils as nat_utils

# Device ID
#DEVICE_ID = 0
# Features supported by the device
#FEATURES = [
#    {'name': 'gRPC', 'port': 12345},
#    {'name': 'SSH', 'port': 22}
#]
# Loopback IP address of the controller
#CONTROLLER_IP = '::1'
DEFAULT_PYMERANG_SERVER_IP = '2000::1'
# Port of the gRPC server executing on the controller
DEFAULT_PYMERANG_SERVER_PORT = 50061
# Loopback IP address of the device
DEFAULT_PYMERANG_CLIENT_IP = 'fcff:1::1'
# Configuration of STUN server/client
#STUN_SOURCE_IP = DEVICE_IP
#STUN_SOURCE_PORT = 50031
#STUN_SERVER_HOST = CONTROLLER_IP
#STUN_SERVER_PORT = 3478
# Souce IP address of the NAT discovery
#DEFAULT_NAT_DISCOVERY_CLIENT_IP = '2000:0:0:1::1'
DEFAULT_NAT_DISCOVERY_CLIENT_IP = '0.0.0.0'
#DEFAULT_NAT_DISCOVERY_CLIENT_IPV6 = '::'
#DEFAULT_NAT_DISCOVERY_CLIENT_IPV4 = '0.0.0.0'
# Source port of the NAT discovery
DEFAULT_NAT_DISCOVERY_CLIENT_PORT = 4789
# IP address of the NAT discovery
DEFAULT_NAT_DISCOVERY_SERVER_IP = '2000::1'
# Port number of the NAT discovery
#DEFAULT_NAT_DISCOVERY_SERVER_PORT = 50081
DEFAULT_NAT_DISCOVERY_SERVER_PORT = 3478
# Config file
DEFAULT_CONFIG_FILE = '/tmp/config.json'
# Default interval between two keep alive messages
DEFAULT_KEEP_ALIVE_INTERVAL = 30


class PymerangDevice:

    def __init__(self, server_ip, server_port, nat_discovery_server_ip,
            nat_discovery_server_port, nat_discovery_client_ip,
            nat_discovery_client_port, config_file, keep_alive_interval=30):
        self.server_ip = server_ip
        self.server_port = server_port
        self.nat_discovery_server_ip = nat_discovery_server_ip
        self.nat_discovery_server_port = nat_discovery_server_port
        self.nat_discovery_client_ip = nat_discovery_client_ip
        self.nat_discovery_client_port = nat_discovery_client_port
        #self.config_file = config_file
        self.nat_type = None
        self.external_ip = None
        self.external_port = None
        self.tunnel_mode = None

        with open(config_file, 'r') as json_file:
            config = json.load(json_file)
        self.device_id = config['id']
        self.features = config['features']
        self.keep_alive_interval = keep_alive_interval

    def process_configuration(self, configuration):
        pass

    def register_device(self, stub):
        # Initialize tunnel state
        tunnel_state = utils.TunnelState(server_ip)
        # Run the stun test to discover the NAT type
        nat_type, external_ip, external_port = pynat.get_ip_info(self.nat_discovery_client_ip,
                                                                 self.nat_discovery_client_port,
                                                                 self.nat_discovery_server_ip,
                                                                 self.nat_discovery_server_port)
        #nat_type, external_ip, external_port = nat_discovery_client.run_nat_discovery_client(
        #    self.nat_discovery_client_ip, self.nat_discovery_client_port,
        #    self.nat_discovery_server_ip, self.nat_discovery_server_port
        #)
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
        if self.tunnel_mode is None:
            print('No tunnel mode supporting the NAT type')
            exit(-1)
        logging.info('Tunnel mode selected: %s' % self.tunnel_mode.name)
        
        # Prepare the registration message
        request = pymerang_pb2.RegisterDeviceRequest()
        request.device.id = self.device_id

        print('\n\n\ndev id', self.device_id)
        for feature in self.features:
            f = request.device.features.add()
            f.name = feature['name']
            if feature.get('port') is not None:
                f.port = feature['port']
        interfaces = utils.get_local_interfaces()
        for ifname, ifinfo in interfaces.items():
            interface = request.interfaces.add()
            interface.name = ifname
            for addr in ifinfo['mac_addrs']:
                mac_addr = interface.mac_addrs.add()
                if addr.get('broadcast') is not None:
                    mac_addr.broadcast = addr['broadcast']
                if addr.get('addr') is not None:
                    mac_addr.addr = addr['addr']
            for addr in ifinfo['ipv4_addrs']:
                ipv4_addr = interface.ipv4_addrs.add()
                if addr.get('broadcast') is not None:
                    ipv4_addr.broadcast = addr['broadcast']
                if addr.get('netmask') is not None:
                    ipv4_addr.netmask = addr['netmask']
                if addr.get('addr') is not None:
                    ipv4_addr.addr = addr['addr']
                if ifname != 'lo':
                    print('\n\n\naddress for nat testing', addr['addr'])
                    # Run the stun test to discover the NAT type
                    nat_type, external_ip, external_port = pynat.get_ip_info(addr['addr'],
                                                                            self.nat_discovery_client_port,
                                                                            self.nat_discovery_server_ip,
                                                                            self.nat_discovery_server_port)
                    #nat_type, external_ip, external_port = nat_discovery_client.run_nat_discovery_client(
                    #    self.nat_discovery_client_ip, self.nat_discovery_client_port,
                    #    self.nat_discovery_server_ip, self.nat_discovery_server_port
                    #)
                    if external_ip is not None:
                        ipv4_addr.ext_addr = external_ip
            for addr in ifinfo['ipv6_addrs']:
                ipv6_addr = interface.ipv6_addrs.add()
                if addr.get('broadcast') is not None:
                    ipv6_addr.broadcast = addr['broadcast']
                if addr.get('netmask') is not None:
                    ipv6_addr.netmask = addr['netmask']
                if addr.get('addr') is not None:
                    ipv6_addr.addr = addr['addr']
                if ifname != 'lo':
                    print('\n\n\naddress for nat testing', addr['addr'].split('%')[0])
                    # Run the stun test to discover the NAT type
                    try:
                        nat_type, external_ip, external_port = pynat.get_ip_info(addr['addr'].split('%')[0],
                                                                                self.nat_discovery_client_port,
                                                                                self.nat_discovery_server_ip,
                                                                                self.nat_discovery_server_port)
                        #nat_type, external_ip, external_port = nat_discovery_client.run_nat_discovery_client(
                        #    self.nat_discovery_client_ip, self.nat_discovery_client_port,
                        #    self.nat_discovery_server_ip, self.nat_discovery_server_port
                        #)
                        if external_ip is not None:
                            ipv6_addr.ext_addr = external_ip
                    except OSError as e:
                        print(e)
        tunnel_info = request.tunnel_info
        #tunnel_info.tunnel_mode = nat_utils.NAT_TYPES[self.nat_type]
        tunnel_info.tunnel_mode = utils.TUNNEL_MODES[self.tunnel_mode.name]
        tunnel_info.device_id = self.device_id
        if self.external_ip is not None:
            tunnel_info.device_external_ip = self.external_ip
            tunnel_info.device_external_port = self.external_port
        print('tun info', tunnel_info)
        # Create the tunnel
        self.tunnel_mode.create_tunnel_device_endpoint(tunnel_info)
        
        print('tun info 2', tunnel_info)
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
            self.tunnel_mode.create_tunnel_device_endpoint_end(tunnel_info)
            # Get the controller address
            controller_ip = self.tunnel_mode.get_controller_ip(self.device_id)
            if controller_ip is None:
                controller_ip = self.server_ip
            self.controller_ip = controller_ip
            # Send a keep-alive messages to keep the tunnel opened, if required
            if self.tunnel_mode.require_keep_alive_messages:
                #Thread(target=utils.start_keep_alive_udp, args=(controller_ip, 50000, 3), daemon=False).start()
                Thread(target=utils.start_keep_alive_icmp, args=(controller_ip, self.keep_alive_interval, 3,  lambda: self.update_device_registration(stub, tunnel_info)), daemon=False).start()
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

    def unregister_device(self, device_id, tunnel_info):
        # Get tunnel info
        #tunnel_info = self.tunnel_info
        # Destroy the tunnel
        self.tunnel_mode.destroy_tunnel_device_endpoint(tunnel_info)

    def update_device_registration(self, stub, tunnel_info):
        self.tunnel_mode.destroy_tunnel_device_endpoint(tunnel_info)
        self.register_device(stub)

    def run(self):
        # Establish a gRPC connection to the controller
        if nat_utils.getAddressFamily(self.server_ip) == AF_INET6:
            server_address = '[%s]:%s' % (self.server_ip, self.server_port)
        elif nat_utils.getAddressFamily(self.server_ip) == AF_INET:
            server_address = '%s:%s' % (self.server_ip, self.server_port)
        else:
            print('Invalid address %s' % self.server_ip)
            exit(-1)
        with grpc.insecure_channel(server_address) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            logging.info("-------------- GetConfiguration --------------")
            # Start registration procedure
            self.register_device(stub)


# Parse options
def parse_arguments():
    # Get parser
    parser = ArgumentParser(
        description='pymerang client'
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Activate debug logs'
    )
    parser.add_argument(
        '-s', '--secure', action='store_true', help='Activate secure mode'
    )
    parser.add_argument(
        '-i', '--server-ip', dest='server_ip',
        default=DEFAULT_PYMERANG_SERVER_IP, help='Server IP address'
    )
    parser.add_argument(
        '-p', '--server-port', dest='server_port',
        default=DEFAULT_PYMERANG_SERVER_PORT, help='Server port'
    )
    parser.add_argument(
        '-n', '--nat-discovery-server-ip', dest='nat_discovery_server_ip',
        default=DEFAULT_NAT_DISCOVERY_SERVER_IP, help='NAT discovery server IP'
    )
    parser.add_argument(
        '-m', '--nat-discovery-server-port', type=int, dest='nat_discovery_server_port',
        default=DEFAULT_NAT_DISCOVERY_SERVER_PORT, help='NAT discovery server port'
    )
    parser.add_argument(
        '-l', '--nat-discovery-client-ip', dest='nat_discovery_client_ip',
        default=DEFAULT_NAT_DISCOVERY_CLIENT_IP, help='NAT discovery client IP'
    )
    parser.add_argument(
        '-o', '--nat-discovery-client-port', type=int, dest='nat_discovery_client_port',
        default=DEFAULT_NAT_DISCOVERY_CLIENT_PORT, help='NAT discovery client port'
    )
    parser.add_argument(
        '-c', '--config-file', dest='config_file',
        default=DEFAULT_CONFIG_FILE, help='Config file'
    )
    parser.add_argument(
        '-k', '--keep-alive-interval', dest='keep_alive_interval',
        default=DEFAULT_KEEP_ALIVE_INTERVAL, help='Interval between two consecutive keep alive'
    )
    # Parse input parameters
    args = parser.parse_args()
    # Return the arguments
    return args

if __name__ == '__main__':
    args = parse_arguments()
    # Setup properly the logger
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
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
    # Start client
    client = PymerangDevice(server_ip, server_port, nat_discovery_server_ip,
        nat_discovery_server_port, nat_discovery_client_ip,
        nat_discovery_client_port, config_file, keep_alive_interval)
    client.run()
