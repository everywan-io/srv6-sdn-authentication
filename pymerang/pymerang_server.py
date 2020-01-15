#!/usr/bin/env python

from concurrent import futures
from multiprocessing import Process
from threading import Thread
from ipaddress import IPv6Network, IPv4Network
from socket import AF_INET, AF_INET6
import logging
import time
import inspect

from pymerang import utils
from pymerang import tunnel_utils
#from pymerang import nat_utils

import grpc

from pymerang import pymerang_pb2
from pymerang import pymerang_pb2_grpc
from pymerang import status_codes_pb2

# Loopback IP address of the controller
DEFAULT_PYMERANG_SERVER_IP = '::'
# Port of the gRPC server executing on the controller
DEFAULT_PYMERANG_SERVER_PORT = 50061
# IP address of the NAT discovery
#NAT_DISCOVERY_SERVER_HOST = '::1'
# Port number of the NAT discovery
#NAT_DISCOVERY_SERVER_PORT = 50081
# Default interval between two keep alive messages
DEFAULT_KEEP_ALIVE_INTERVAL = 30


class PymerangServicer(pymerang_pb2_grpc.PymerangServicer):
    """Provides methods that implement functionality of route guide server."""

    def __init__(self, controller):
        self.controller = controller

    def RegisterDevice(self, request, context):
        # Extract the parameters from the registration request
        logging.debug('New device connected: %s' % request)
        mgmtip = context.peer()
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        device_id = request.device.id
        features = dict()
        for feature in request.device.features:
            name = feature.name
            port = feature.port
            features[name] = {name: name, port: port}
        auth_data = request.auth_data
        interfaces = dict()
        for interface in request.interfaces:
            ifname = interface.name
            mac_addrs = list()
            ipv4_addrs = list()
            ipv6_addrs = list()
            for mac_addr in interface.mac_addrs:
                mac_addrs.append({
                    'broadcast': mac_addr.broadcast,
                    'addr': mac_addr.addr
                })
            for ipv4_addr in interface.ipv4_addrs:
                prefix = ipv4_addr.netmask.split('/')
                if len(prefix) > 1:
                    ipv4_addr.netmask = prefix[1]
                ipv4_addrs.append({
                    'broadcast': ipv4_addr.broadcast,
                    'netmask': str(IPv4Network('0.0.0.0/%s' % ipv4_addr.netmask).prefixlen),
                    'addr': ipv4_addr.addr
                })
            for ipv6_addr in interface.ipv6_addrs:
                prefix = ipv6_addr.netmask.split('/')
                if len(prefix) > 1:
                    ipv6_addr.netmask = prefix[1]
                ipv6_addrs.append({
                    'broadcast': ipv6_addr.broadcast,
                    'netmask': ipv6_addr.netmask,
                    'addr': ipv6_addr.addr.split('%')[0]
                })
            interfaces[ifname] = {
                'name': ifname,
                'mac_addrs': mac_addrs,
                'ipv4_addrs': ipv4_addrs,
                'ipv6_addrs': ipv6_addrs,
                'ipv4_subnets': list(),
                'ipv6_subnets': list(),
                'type': utils.InterfaceType.UNKNOWN,
            }
        tunnel_info = request.tunnel_info
        # Register the device
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.device_id = tunnel_info.device_id
        reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = tunnel_info.device_external_port
        response, tunnel_info = self.controller.register_device(
            device_id, features, interfaces, mgmtip, auth_data, reply.tunnel_info
        )
        if response is not status_codes_pb2.STATUS_OK:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Generate the configuration for the device
        #config = self.controller.devices[device_id]['device_configuration']
        #config = self.controller.configurations[device_id]
        reply.status = status_codes_pb2.STATUS_OK
        #reply.device_configuration =       # TODO
        return reply

    def UpdateDeviceRegistration(self, request, context):
        # Extract the parameters from the registration request
        logging.debug('Update device registration: %s' % request)
        #mgmtip = context.peer()
        #mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        device_id = request.device.id
        #features = dict()
        #for feature in request.device.features:
        #    name = feature.name
        #    port = feature.port
        #    features[name] = {name: name, port: port}
        #auth_data = request.auth_data
        #interfaces = dict()
        #for interface in request.interfaces:
        #    ifname = interface.name
        #    mac_addrs = list()
        #    ipv4_addrs = list()
        #    ipv6_addrs = list()
        #    for mac_addr in interface.mac_addrs:
        #        mac_addrs.append({
        #            'broadcast': mac_addr.broadcast,
        #            'addr': mac_addr.addr
        #        })
        #    for ipv4_addr in interface.ipv4_addrs:
        #        prefix = ipv4_addr.netmask.split('/')
        #        if len(prefix) > 1:
        #            ipv4_addr.netmask = prefix[1]
        #        ipv4_addrs.append({
        #            'broadcast': ipv4_addr.broadcast,
        #            'netmask': str(IPv4Network('0.0.0.0/%s' % ipv4_addr.netmask).prefixlen),
        #            'addr': ipv4_addr.addr
        #        })
        #    for ipv6_addr in interface.ipv6_addrs:
        #        prefix = ipv6_addr.netmask.split('/')
        #        if len(prefix) > 1:
        #            ipv6_addr.netmask = prefix[1]
        #        ipv6_addrs.append({
        #            'broadcast': ipv6_addr.broadcast,
        #            'netmask': ipv6_addr.netmask,
        #            'addr': ipv6_addr.addr.split('%')[0]
        #        })
        #    interfaces[ifname] = {
        #        'mac_addrs': mac_addrs,
        #        'ipv4_addrs': ipv4_addrs,
        #        'ipv6_addrs': ipv6_addrs,
        #    }
        tunnel_info = request.tunnel_info
        # Register the device
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.device_id = tunnel_info.device_id
        #reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = tunnel_info.device_external_port
        response, tunnel_info = self.controller.update_device_registration(
            device_id, reply.tunnel_info
        )
        if response is not status_codes_pb2.STATUS_OK:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Generate the configuration for the device
        #config = self.controller.devices[device_id]['device_configuration']
        #config = self.controller.configurations[device_id]
        reply.status = status_codes_pb2.STATUS_OK
        #reply.device_configuration =       # TODO
        return reply
        

class PymerangController:

    def __init__(self, server_ip='::1', server_port=50051, devices=None, keep_alive_interval=30):
        self.server_ip = server_ip
        self.server_port = server_port
        if devices is not None:
            self.devices = devices
        else:
            self.devices = dict()
        self.configurations = dict()
        self.tunnel_state = None
        self.tunnel_modes = dict()
        self.keep_alive_interval = keep_alive_interval

    def authenticate_device(self, device_id, auth_data):
        return True     # TODO

    def register_device(self, device_id, features, interfaces, mgmtip, auth_data, tunnel_info):
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
        self.devices[device_id]['interfaces'] = interfaces
        print('TUNNEL DeV IP', tunnel_mode.device_ip)
        if tunnel_mode.get_device_ip(device_id) is not None:
            mgmtip = tunnel_mode.get_device_ip(device_id)
            print('mgmtmgmtmgmtmgmtm', mgmtip)
        self.devices[device_id]['mgmtip'] = mgmtip
        self.devices[device_id]['tunnel_mode'] = tunnel_info.tunnel_mode
        self.devices[device_id]['tunnel_info'] = tunnel_info
        self.devices[device_id]['status'] = utils.DeviceStatus.CONNECTED
        self.tunnel_modes[device_id] = tunnel_mode
        # Send a keep-alive messages to keep the tunnel opened, if required
        if tunnel_mode.require_keep_alive_messages:
            #Thread(target=utils.start_keep_alive_udp, args=(controller_ip, 50000, 3), daemon=False).start()
            Thread(target=utils.start_keep_alive_icmp, args=(mgmtip, self.keep_alive_interval, 3), daemon=False).start()
        logging.info('New device registered: %s' % self.devices[device_id])
        # Return the configuration
        return status_codes_pb2.STATUS_OK, tunnel_info

    def update_device_registration(self, device_id, tunnel_info):
        # Device authentication
        #authenticated = self.authenticate_device(device_id, auth_data)
        #if not authenticated:
        #    return status_codes_pb2.STATUS_UNAUTHORIZED, None
        # Get the tunnel mode required by the device
        #tunnel_mode = utils.REVERSE_TUNNEL_MODES[tunnel_info.tunnel_mode]
        #tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
        # Create the tunnel
        tunnel_mode = self.tunnel_modes[device_id]
        tunnel_mode.update_tunnel_controller_endpoint(device_id, tunnel_info)
        # Register the device
        #self.devices[device_id] = dict()
        #self.devices[device_id]['features'] = features
        #self.devices[device_id]['interfaces'] = interfaces
        #print('TUNNEL DeV IP', tunnel_mode.device_ip)
        #if tunnel_mode.get_device_ip(device_id) is not None:
        #    mgmtip = tunnel_mode.get_device_ip(device_id)
        #    print('mgmtmgmtmgmtmgmtm', mgmtip)
        #self.devices[device_id]['mgmtip'] = mgmtip
        #self.devices[device_id]['tunnel_mode'] = tunnel_info.tunnel_mode
        #self.devices[device_id]['tunnel_info'] = tunnel_info
        #self.tunnel_modes[device_id] = tunnel_mode
        logging.info('New device registered: %s' % self.devices[device_id])
        # Return the configuration
        return status_codes_pb2.STATUS_OK, tunnel_info

    def unregister_device(self, device_id):
        # Get the tunnel mode
        tunnel_mode = self.devices[device_id]['tunnel_mode']
        tunnel_info = self.devices[device_id]['tunnel_info']
        del self.tunnel_modes[device_id]
        # Destroy the tunnel
        tunnel_mode.destroy_tunnel_controller_endpoint(tunnel_info)

    def load_device_config(self):
        #self.devices[0] = dict()
        #self.devices[0]['device_configuration'] = {}
        self.configurations = {
            1: {},
            2: {},
            3: {},
        }

    def serve(self):
        # Initialize tunnel state
        self.tunnel_state = utils.TunnelState(self.server_ip)
        # Start gRPC server
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        pymerang_pb2_grpc.add_PymerangServicer_to_server(
            PymerangServicer(self), server
        )
        print(self.server_ip)
        if tunnel_utils.getAddressFamily(self.server_ip) == AF_INET6:
            print('IPv6')
            server_address = '[%s]:%s' % (self.server_ip, self.server_port)
        elif tunnel_utils.getAddressFamily(self.server_ip) == AF_INET:
            print('IPv4')
            server_address = '%s:%s' % (self.server_ip, self.server_port)
        else:
            logging.error('Invalid server address %s' % self.server_ip)
            return
        #server_address = '[%s]:%s' % ('::', self.server_port)
        logging.info('Server started: listening on %s' % server_address)
        server.add_insecure_port(server_address)
        server.start()
        #server.wait_for_termination()
        while True:
            time.sleep(10)


# Parse options
def parse_arguments():
    # Get parser
    parser = ArgumentParser(
        description='pymerang server'
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
        '-k', '--keep-alive-interval', dest='kee_alive_interval',
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
    # Devices
    devices = dict()
    # Keep alive interval
    keep_alive_interval = args.keep_alive_interval
    # Start server
    controller = PymerangController(server_ip, server_port, devices, keep_alive_interval)
    controller.load_device_config()
    controller.serve()
