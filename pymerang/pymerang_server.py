#!/usr/bin/env python

# General imports
from argparse import ArgumentParser
from concurrent import futures
from threading import Thread
from socket import AF_INET, AF_INET6
import logging
import time
import grpc
# pymerang dependencies
from pymerang import utils
from pymerang import tunnel_utils
from pymerang import pymerang_pb2
from pymerang import pymerang_pb2_grpc
from pymerang import status_codes_pb2
# SRv6 dependencies
from srv6_sdn_controller_state import srv6_sdn_controller_state

# Loopback IP address of the controller
DEFAULT_PYMERANG_SERVER_IP = '::'
# Port of the gRPC server executing on the controller
DEFAULT_PYMERANG_SERVER_PORT = 50061
# Default interval between two keep alive messages
DEFAULT_KEEP_ALIVE_INTERVAL = 30

# Default VXLAN port
DEFAULT_VXLAN_PORT = 4789

# Status codes
STATUS_SUCCESS = status_codes_pb2.STATUS_SUCCESS
STATUS_UNAUTHORIZED = status_codes_pb2.STATUS_UNAUTHORIZED
STATUS_INTERNAL_ERROR = status_codes_pb2.STATUS_INTERNAL_ERROR


class PymerangServicer(pymerang_pb2_grpc.PymerangServicer):
    """Provides methods that implement functionality of route guide server."""

    def __init__(self, controller):
        self.controller = controller

    def RegisterDevice(self, request, context):
        logging.info('New device connected: %s' % request)
        # Get the IP address seen by the gRPC server
        # It can be used for management
        mgmtip = context.peer()
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        # Extract the parameters from the registration request
        #
        # Device ID
        device_id = request.device.id
        # Check if the device exists
        #if device_id not in self.controller.devices:
        #    logging.debug('Unauthorized')
        #    return (pymerang_pb2
        #            .RegisterDeviceReply(status=STATUS_UNAUTHORIZED))
        # Features supported by the device
        features = list()
        for feature in request.device.features:
            name = feature.name
            port = feature.port
            features.append({'name': name, 'port': port})
        # Data needed for the device authentication
        auth_data = request.auth_data
        # Interfaces of the devices
        interfaces = list()
        for interface in request.interfaces:
            # Interface name
            ifname = interface.name
            # MAC address
            mac_addr = interface.mac_addr
            # IPv4 addresses
            ipv4_addrs = list(interface.ipv4_addrs)
            # IPv6 addresses
            ipv6_addrs = list(interface.ipv6_addrs)
            # Save the interface
            interfaces.append({
                'name': ifname,
                'mac_addr': mac_addr,
                'ipv4_addrs': ipv4_addrs,
                'ipv6_addrs': ipv6_addrs,
                'ipv4_subnets': list(),
                'ipv6_subnets': list(),
                'ext_ipv4_addrs': list(),
                'ext_ipv6_addrs': list(),
                'type': utils.InterfaceType.UNKNOWN,
            })
        # Extract tunnel information
        tunnel_info = request.tunnel_info
        # Prepare the response message
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.device_id = tunnel_info.device_id
        reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = \
            tunnel_info.device_external_port
        reply.tunnel_info.device_vtep_mac = tunnel_info.device_vtep_mac
        # Register the device
        logging.debug('Trying to register the device %s' % device_id)
        response, tunnel_info, port, tenantid = self.controller.register_device(
            device_id, features, interfaces,
            mgmtip, auth_data, reply.tunnel_info
        )
        if response != STATUS_SUCCESS:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Set the status code
        reply.status = STATUS_SUCCESS
        reply.vxlan_port = port
        reply.tunnel_info.vxlan_port = port
        reply.tunnel_info.tenantid = tenantid
        # Send the reply
        logging.info('Sending the reply: %s' % reply)
        return reply

    def UpdateTunnelMode(self, request, context):
        logging.info('Establish tunnel connection: %s' % request)
        # Get the IP address seen by the gRPC server
        # It can be used for management
        mgmtip = context.peer()
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        # Extract the parameters from the registration request
        #
        # Device ID
        device_id = request.device.id
        # Interfaces of the devices
        interfaces = dict()
        for interface in request.interfaces:
            # Interface name
            ifname = interface.name
            # IPv4 addresses
            ipv4_addrs = list(interface.ext_ipv4_addrs)
            # IPv6 addresses
            ipv6_addrs = list(interface.ext_ipv6_addrs)
            # Save the interface
            interfaces[ifname] = {
                'name': ifname,
                'ext_ipv4_addrs': ipv4_addrs,
                'ext_ipv6_addrs': ipv6_addrs
            }
        # Extract tunnel information
        tunnel_info = request.tunnel_info
        # Extract tunnel mode
        tunnel_mode = request.tunnel_mode
        # Extract NAT type
        nat_type = request.nat_type
        # Prepare the response message
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.device_id = tunnel_info.device_id
        reply.tunnel_info.tenantid = tunnel_info.tenantid
        reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = \
            tunnel_info.device_external_port
        reply.tunnel_info.device_vtep_mac = tunnel_info.device_vtep_mac
        reply.tunnel_info.vxlan_port = tunnel_info.vxlan_port
        # Register the device
        logging.debug('Trying to register the device %s' % device_id)
        response, tunnel_info = self.controller.update_tunnel_mode(
            device_id, interfaces, mgmtip, reply.tunnel_info,
            tunnel_mode, nat_type
        )
        if response != STATUS_SUCCESS:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Set the status code
        reply.status = STATUS_SUCCESS
        # Send the reply
        logging.info('Sending the reply: %s' % reply)
        return reply

    def UpdateDeviceRegistration(self, request, context):
        logging.info('Update device registration: %s' % request)
        # Get the IP address seen by the gRPC server
        # It can be used for management
        mgmtip = context.peer()
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        # Extract the parameters from the registration request
        #
        # Device ID
        device_id = request.device.id
        # Interfaces of the devices
        interfaces = dict()
        for interface in request.interfaces:
            # Interface name
            ifname = interface.name
            # MAC address
            mac_addr = interface.mac_addr
            # IPv4 addresses
            ipv4_addrs = list(interface.ipv4_addrs)
            # IPv6 addresses
            ipv6_addrs = list(interface.ipv6_addrs)
            # Save the interface
            interfaces[ifname] = {
                'name': ifname,
                'mac_addr': mac_addr,
                'ipv4_addrs': ipv4_addrs,
                'ipv6_addrs': ipv6_addrs,
                'ipv4_subnets': list(),
                'ipv6_subnets': list(),
                'ext_ipv4_addrs': list(),
                'ext_ipv6_addrs': list(),
                'type': utils.InterfaceType.UNKNOWN,
            }
        # Extract tunnel information
        tunnel_info = request.tunnel_info
        # Prepare the reply message
        reply = pymerang_pb2.RegisterDeviceReply()
        reply.tunnel_info.device_id = tunnel_info.device_id
        reply.tunnel_info.tunnel_mode = tunnel_info.tunnel_mode
        reply.tunnel_info.device_external_ip = tunnel_info.device_external_ip
        reply.tunnel_info.device_external_port = \
            tunnel_info.device_external_port
        reply.tunnel_info.device_vtep_mac = tunnel_info.device_vtep_mac
        # Update the device registration
        logging.debug('Trying to update the device registration for device %s'
                      % device_id)
        response, tunnel_info = self.controller.update_device_registration(
            device_id, None, interfaces, mgmtip, None, reply.tunnel_info
        )
        if response is not STATUS_SUCCESS:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Set the status code
        reply.status = STATUS_SUCCESS
        # Send the reply
        logging.info('Sending the reply: %s' % reply)
        return reply

    def UnregisterDevice(self, request, context):
        logging.info('Unregister device request: %s' % request)
        # Extract the parameters from the registration request
        #
        # Device ID
        device_id = request.device.id
        # Extract tunnel information
        tunnel_info = request.tunnel_info
        # Unregister the device
        logging.debug('Trying to unregister the device %s'
                      % device_id)
        response, tunnel_info = self.controller.unregister_device(
            device_id
        )
        if response is not STATUS_SUCCESS:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Send the reply
        reply = pymerang_pb2.RegisterDeviceReply(
            status=STATUS_SUCCESS
        )
        logging.info('Sending the reply: %s' % reply)
        return reply


class PymerangController:

    def __init__(self, server_ip='::1', server_port=50051,
                 keep_alive_interval=30):
        # IP address on which the gRPC listens for connections
        self.server_ip = server_ip
        # Port used by the gRPC server
        self.server_port = server_port
        # Tunnel state
        self.tunnel_state = None
        # Interval between two consecutive keep alive messages
        self.keep_alive_interval = keep_alive_interval

    # Restore management interfaces, if any
    def restore_mgmt_interfaces(self):
        logging.info('*** Restoring management interfaces')
        tunnel_info = pymerang_pb2.TunnelInfo()
        # Get all the devices
        devices = srv6_sdn_controller_state.get_devices()
        if devices is None:
            logging.error('Cannot retrieve devices list')
            return
        for device in devices:
            tunnel_mode = device['tunnel_mode']
            tunnel_info.device_id = device['deviceid']
            if device.get('external_ip') is not None:
                tunnel_info.device_external_ip = device['external_ip']
            if device.get('external_port') is not None:
                tunnel_info.device_external_port = device['external_port']
            if device.get('mgmt_mac') is not None:
                tunnel_info.device_vtep_mac = device['mgmt_mac']
            if device.get('vxlan_port') is not None:
                tunnel_info.vxlan_port = device['vxlan_port']
            if tunnel_mode is not None:
                logging.info('Restoring management interface for device %s'
                             % device['deviceid'])
                # Create tunnel controller endpoint
                tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
                res = tunnel_mode.create_tunnel_controller_endpoint(
                    tunnel_info)
                if res != STATUS_SUCCESS:
                    logging.warning('Cannot restore the tunnel on device %s'
                                    % device['deviceid'])
                    return res, None

    # Authenticate a device
    def authenticate_device(self, device_id, auth_data):
        logging.info('Authenticating the device %s' % device_id)
        # Get token, tenant ID and VXLAN port
        token = auth_data.token
        authenticated, tenantid = srv6_sdn_controller_state.authenticate_device(token)
        if not authenticated:
            return False, None
        return True, tenantid

    # Register a device
    def register_device(self, device_id, features,
                        interfaces, mgmtip, auth_data, tunnel_info):
        logging.info('Registering the device %s' % device_id)
        # If the device is already registered, send it the configuration
        # and create tunnels
        if srv6_sdn_controller_state.device_exists(device_id):
            logging.warning('The device %s is already registered' % device_id)
            # TODO configure device
            # TODO create tunnels
        # Device authentication
        authenticated, tenantid = self.authenticate_device(
            device_id, auth_data)
        if not authenticated:
            logging.info('Authentication failed for the device %s' % device_id)
            return STATUS_UNAUTHORIZED, None, None, None
        # Update controller state
        srv6_sdn_controller_state.register_device(device_id, features, interfaces, mgmtip, tenantid)
        # Get the tenant configuration
        config = srv6_sdn_controller_state.get_tenant_config(tenantid)
        if config is None:
            logging.error('Tenant not found or error while connecting to the db')
            return STATUS_INTERNAL_ERROR, None, None, None
        # Set the port
        port = config.get('vxlan_port', DEFAULT_VXLAN_PORT)
        if port is None:
            port = tunnel_info.device_external_port
        # Success
        logging.debug('New device registered:\n%s' % device_id)
        return STATUS_SUCCESS, tunnel_info, port, tenantid

    # Update tunnel mode
    def update_tunnel_mode(self, device_id, interfaces, mgmtip,
                           tunnel_info, tunnel_mode, nat_type):
        logging.info('Updating the tunnel for the device %s' % device_id)
        
        tunnel_name = tunnel_mode
        
        deviceid = tunnel_info.device_id
        tenantid = tunnel_info.tenantid
        
        # If a tunnel already exists, we need to destroy it
        # before creating the new tunnel
        #old_tunnel_mode = self.devices[device_id]['tunnel_mode']
        old_tunnel_mode = srv6_sdn_controller_state.get_tunnel_mode(deviceid)
        if old_tunnel_mode is not None:
            #old_tunnel_mode = utils.REVERSE_TUNNEL_MODES[old_tunnel_mode]
            old_tunnel_mode = self.tunnel_state.tunnel_modes[old_tunnel_mode]
            old_tunnel_mode.destroy_tunnel_controller_endpoint(deviceid, tenantid)
            srv6_sdn_controller_state.set_tunnel_mode(deviceid, None)
            #self.devices[device_id]['tunnel_mode'] = None
            
        # Get the tunnel mode requested by the device
        tunnel_mode = utils.REVERSE_TUNNEL_MODES[tunnel_info.tunnel_mode]
        tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
        # Get the tenant ID
        #tenantid = self.devices[device_id]['tenantid']
        #tunnel_info.tenantid = tenantid
        # Create the tunnel
        logging.info('Trying to create the tunnel for the device %s'
                     % device_id)
        res = tunnel_mode.create_tunnel_controller_endpoint(tunnel_info)
        if res != STATUS_SUCCESS:
            logging.warning('Cannot create the tunnel')
            return res, None
        # Store tunnel mode
        #self.devices[device_id]['tunnel_mode'] = tunnel_info.tunnel_mode
        # Store tunnel info
        #self.devices[device_id]['tunnel_info'] = tunnel_info
        # If a private IP address is present, use it as mgmt address
        if srv6_sdn_controller_state.get_device_mgmtip(tenantid, device_id) is not None:
            mgmtip = srv6_sdn_controller_state.get_device_mgmtip(tenantid, device_id).split('/')[0]
            #self.devices[device_id]['mgmtip'] = mgmtip
        # Update mapping device to tunnel mode
        #self.device_to_tunnel_mode[device_id] = tunnel_mode
        # Send a keep-alive messages to keep the tunnel opened,
        # if required for the tunnel mode
        if tunnel_mode.require_keep_alive_messages:
            Thread(target=utils.start_keep_alive_icmp, args=(
                mgmtip, self.keep_alive_interval, 3,
                lambda: self.device_disconnected(device_id, None)),
                   daemon=False).start()
        # Set the tenant ID
        #tunnel_info.tenantid = tenantid
        # Update the tunnel
        #logging.debug('Trying to update the tunnel for the device %s' % device_id)
        #tunnel_mode = self.device_to_tunnel_mode[device_id]
        #tunnel_mode.update_tunnel_controller_endpoint(device_id, tunnel_info)
        # Update the device information
        #for interface in interfaces.values():
        #    name = interface['name']
        #    ext_ipv4_addrs = interface['ext_ipv4_addrs']
        #    ext_ipv6_addrs = interface['ext_ipv6_addrs']
        #    self.devices[device_id]['interfaces'][name]['ext_ipv4_addrs'] = ext_ipv4_addrs
        #    self.devices[device_id]['interfaces'][name]['ext_ipv6_addrs'] = ext_ipv6_addrs

        device_external_ip = tunnel_info.device_external_ip
        device_external_port = tunnel_info.device_external_port
        device_vtep_mac = tunnel_info.device_vtep_mac
        vxlan_port = tunnel_info.vxlan_port

        # Update controller state
        srv6_sdn_controller_state.update_tunnel_mode(
            device_id, mgmtip, interfaces, tunnel_name,
            nat_type, device_external_ip,
            device_external_port, device_vtep_mac, vxlan_port)

        # Update the management IP address
        # if tunnel_mode.get_device_private_ip(tenantid, device_id) is not None:
        #    mgmtip = tunnel_mode.get_device_private_ip(tenantid, device_id)
        #self.devices[device_id]['mgmtip'] = mgmtip
        # Success
        logging.debug('Updated device registration: %s' %
                      deviceid)
        return STATUS_SUCCESS, tunnel_info

    def unregister_device(self, device_id, tunnel_info):
        logging.debug('Unregistering the device %s' % device_id)
        # Get the tunnel mode
        #tunnel_mode = self.devices[device_id]['tunnel_mode']
        #tunnel_mode = utils.REVERSE_TUNNEL_MODES[tunnel_mode]
        tunnel_mode = srv6_sdn_controller_state.get_tunnel_mode(device_id)
        tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
        # Get the tunnel info
        #tunnel_info = self.devices[device_id]['tunnel_info']
        # Get the tenant ID of the devices
        #tenantid = self.devices[device_id]['tenantid']
        # Remove the device from the data structures
        #del self.device_to_tunnel_mode[device_id]
        #del self.devices[device_id]
        
        success = srv6_sdn_controller_state.unregister_device(device_id)
        if success is None or success is False:
            err = ('Cannot unregister the device. '
                    'Error while updating the controller state')
            logging.error(err)
            return STATUS_INTERNAL_ERROR, err
        
        # Destroy the tunnel
        logging.debug(
            'Trying to destroy the tunnel for the device %s' % device_id)
        tunnel_mode.destroy_tunnel_controller_endpoint(tunnel_info)
        # Success
        logging.debug('Device unregistered: %s' % device_id)
        return STATUS_SUCCESS, tunnel_info

    def device_disconnected(self, device_id, tunnel_info):
        logging.debug('Unregistering the device %s' % device_id)
        # Get the tunnel mode
        #tunnel_mode = self.devices[device_id]['tunnel_mode']
        #tunnel_mode = utils.REVERSE_TUNNEL_MODES[tunnel_mode]
        tunnel_mode = srv6_sdn_controller_state.get_tunnel_mode(device_id)
        tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
        # Get the tunnel info
        #tunnel_info = self.devices[device_id]['tunnel_info']
        # Get the tenant ID of the devices
        #tenantid = self.devices[device_id]['tenantid']
        tenantid = srv6_sdn_controller_state.get_device(device_id)['tenantid']
        # Remove the device from the data structures
        #del self.device_to_tunnel_mode[device_id]
        #del self.devices[device_id]

        success = srv6_sdn_controller_state.set_device_connected_flag(
            deviceid=device_id, connected=False)
        if success is None or success is False:
            err = ('Cannot set the device as disconnected. '
                   'Error while updating the controller state')
            logging.error(err)
            return STATUS_INTERNAL_ERROR, err

        # Destroy the tunnel
        logging.debug(
            'Trying to destroy the tunnel for the device %s' % device_id)
        tunnel_mode.destroy_tunnel_controller_endpoint(device_id, tenantid)
        # Success
        logging.debug('Device unregistered: %s' % device_id)
        return STATUS_SUCCESS, tunnel_info

    def serve(self):
        # Initialize tunnel state
        self.tunnel_state = utils.TunnelState(self.server_ip)
        # Restore management interfaces, if any
        self.restore_mgmt_interfaces()
        # Start gRPC server
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        pymerang_pb2_grpc.add_PymerangServicer_to_server(
            PymerangServicer(self), server
        )
        if tunnel_utils.getAddressFamily(self.server_ip) == AF_INET6:
            server_address = '[%s]:%s' % (self.server_ip, self.server_port)
        elif tunnel_utils.getAddressFamily(self.server_ip) == AF_INET:
            server_address = '%s:%s' % (self.server_ip, self.server_port)
        else:
            logging.error('Invalid server address %s' % self.server_ip)
            return
        logging.info('Server started: listening on %s' % server_address)
        server.add_insecure_port(server_address)
        server.start()
        # Wait for server termination
        while True:
            time.sleep(10)


# Parse options
def parse_arguments():
    # Get parser
    parser = ArgumentParser(
        description='pymerang server'
    )
    # Debug mode
    parser.add_argument(
        '-d', '--debug', action='store_true', help='Activate debug logs'
    )
    # Secure mode
    parser.add_argument(
        '-s', '--secure', action='store_true', help='Activate secure mode'
    )
    # gRPC server IP
    parser.add_argument(
        '-i', '--server-ip', dest='server_ip',
        default=DEFAULT_PYMERANG_SERVER_IP, help='Server IP address'
    )
    # gRPC server port
    parser.add_argument(
        '-p', '--server-port', dest='server_port',
        default=DEFAULT_PYMERANG_SERVER_PORT, help='Server port'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-k', '--keep-alive-interval', dest='keep_alive_interval',
        default=DEFAULT_KEEP_ALIVE_INTERVAL,
        help='Interval between two consecutive keep alive'
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
        logging.getLogger().setLevel(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(level=logging.INFO)
    # Setup properly the secure mode
    if args.secure:
        secure = True
    else:
        secure = False
    # gRPC server IP
    server_ip = args.server_ip
    # gRPC server port
    server_port = args.server_port
    # Keep alive interval
    keep_alive_interval = args.keep_alive_interval
    # Start server
    controller = PymerangController(server_ip, server_port,
                                    keep_alive_interval)
    controller.serve()
