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
# Max number of keep alive messages lost
# before taking a corrective action
DEFAULT_MAX_KEEP_ALIVE_LOST = 3
# Secure option
DEFAULT_SECURE = False
# Server certificate
DEFAULT_CERTIFICATE = 'cert_server.pem'
# Server key
DEFAULT_KEY = 'key_server.pem'

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
        # Separate IP and port
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        # Extract the parameters from the registration request
        #
        # Device ID
        deviceid = request.device.id
        # Features supported by the device
        features = list()
        for feature in request.device.features:
            name = feature.name
            port = feature.port
            features.append({'name': name, 'port': port})
        # Data needed for the device authentication
        auth_data = request.auth_data
        # Prefix to be used for SRv6 tunnels
        sid_prefix = None
        if request.sid_prefix != '':
            sid_prefix = request.sid_prefix
        # Define whether to enable or not proxy NDP for SIDs advertisement
        enable_proxy_ndp = request.enable_proxy_ndp
        # Public prefix length used to compute SRv6 SID list
        public_prefix_length = 128
        if request.public_prefix_length != 0:
            public_prefix_length = request.public_prefix_length
        # Interfaces of the devices
        interfaces = list()
        for interface in request.interfaces:
            # Interface name
            ifname = interface.name
            # MAC address
            mac_addr = interface.mac_addr
            # IPv4 addresses
            ipv4_addrs = list()
            for addr in interface.ipv4_addrs:
                ipv4_addrs.append(addr)     # TODO add validation checks?
            # IPv6 addresses
            ipv6_addrs = list()
            for addr in interface.ipv6_addrs:
                ipv6_addrs.append(addr)     # TODO add validation checks?
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
        # Prepare the response message
        reply = pymerang_pb2.RegisterDeviceReply()
        # Register the device
        logging.debug('Trying to register the device %s' % deviceid)
        response, vxlan_port, tenantid = \
            self.controller.register_device(
                deviceid, features, interfaces,
                mgmtip, auth_data, sid_prefix,
                public_prefix_length, enable_proxy_ndp
            )
        if response != STATUS_SUCCESS:
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Set the status code
        reply.status = STATUS_SUCCESS
        # Set the VXLAN port
        reply.mgmt_info.vxlan_port = vxlan_port
        # Set the tenant ID
        reply.tenantid = tenantid
        # Send the reply
        logging.info('Device registered succefully. '
                     'Sending the reply: %s' % reply)
        return reply

    def UpdateMgmtInfo(self, request, context):
        logging.info('Establish tunnel connection: %s' % request)
        # Get the IP address seen by the gRPC server
        # It can be used for management
        mgmtip = context.peer()
        # Separate IP and port
        mgmtip = utils.parse_ip_port(mgmtip)[0].__str__()
        # Extract the parameters from the registration request
        #
        # Device ID
        deviceid = request.device.id
        # Tenant ID
        tenantid = request.tenantid
        # Interfaces of the devices
        interfaces = dict()
        for interface in request.interfaces:
            # Interface name
            ifname = interface.name
            # IPv4 addresses
            ipv4_addrs = list()
            for addr in interface.ext_ipv4_addrs:
                ipv4_addrs.append(addr)     # TODO add validation checks?
            # IPv6 addresses
            ipv6_addrs = list()
            for addr in interface.ext_ipv6_addrs:
                ipv6_addrs.append(addr)     # TODO add validation checks?
            # Save the interface
            interfaces[ifname] = {
                'name': ifname,
                'ext_ipv4_addrs': ipv4_addrs,
                'ext_ipv6_addrs': ipv6_addrs
            }
        # Extract tunnel mode
        tunnel_mode = request.mgmt_info.tunnel_mode
        # Extract NAT type
        nat_type = request.mgmt_info.nat_type
        # Extract the external IP address
        device_external_ip = request.mgmt_info.device_external_ip
        # Extract the external port
        device_external_port = request.mgmt_info.device_external_port
        # Extract device VTEP MAC address
        device_vtep_mac = request.mgmt_info.device_vtep_mac
        # Extract VXLAN port
        vxlan_port = request.mgmt_info.vxlan_port
        # Update management information
        logging.debug('Trying to update management information for '
                      'the device %s' % deviceid)
        response, controller_vtep_mac, controller_vtep_ip, device_vtep_ip, \
            vtep_mask = self.controller.update_mgmt_info(
                deviceid, tenantid, interfaces, mgmtip, tunnel_mode, nat_type,
                device_external_ip, device_external_port,
                device_vtep_mac, vxlan_port
            )
        if response != STATUS_SUCCESS:
            logging.error('Cannot update management information')
            return (pymerang_pb2
                    .RegisterDeviceReply(status=response))
        # Create the response
        reply = pymerang_pb2.RegisterDeviceReply()
        # Set the status code
        reply.status = STATUS_SUCCESS
        # Set the controller VTEP MAC
        if controller_vtep_mac is not None:
            reply.mgmt_info.controller_vtep_mac = controller_vtep_mac
        # Set the controller VTEP IP
        if controller_vtep_ip is not None:
            reply.mgmt_info.controller_vtep_ip = controller_vtep_ip
        # Set the device VTEP IP
        if device_vtep_ip is not None:
            reply.mgmt_info.device_vtep_ip = device_vtep_ip
        # Set the VTEP mask
        if vtep_mask is not None:
            reply.mgmt_info.vtep_mask = vtep_mask
        # Send the reply
        logging.info('Sending the reply: %s' % reply)
        return reply

    def UnregisterDevice(self, request, context):
        logging.info('Unregister device request: %s' % request)
        # Extract the parameters from the registration request
        #
        # Device ID
        deviceid = request.device.id
        # Tenant ID
        tenantid = request.tenantid
        # Unregister the device
        logging.debug('Trying to unregister the device %s'
                      % deviceid)
        response = self.controller.unregister_device(
            deviceid, tenantid
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
                 keep_alive_interval=DEFAULT_KEEP_ALIVE_INTERVAL,
                 max_keep_alive_lost=DEFAULT_MAX_KEEP_ALIVE_LOST,
                 secure=DEFAULT_SECURE, key=DEFAULT_KEY,
                 certificate=DEFAULT_CERTIFICATE):
        # IP address on which the gRPC listens for connections
        self.server_ip = server_ip
        # Port used by the gRPC server
        self.server_port = server_port
        # Tunnel state
        self.tunnel_state = None
        # Interval between two consecutive keep alive messages
        self.keep_alive_interval = keep_alive_interval
        # Max keep alive lost
        self.max_keep_alive_lost = max_keep_alive_lost
        # Secure mode
        self.secure = secure
        # Server key
        self.key = key
        # Certificate
        self.certificate = certificate

    # Restore management interfaces, if any
    def restore_mgmt_interfaces(self):
        logging.info('*** Restoring management interfaces')
        # Get all the devices
        devices = srv6_sdn_controller_state.get_devices()
        if devices is None:
            logging.error('Cannot retrieve devices list')
            return
        # Iterate on the devices list
        for device in devices:
            # Get the ID of the device
            deviceid = device['deviceid']
            # Get the ID of the tenant
            tenantid = device['tenantid']
            # Get the tunnel mode used for this device
            tunnel_mode = device.get('tunnel_mode')
            # If tunnel mode is valid, restore the tunnel endpoint
            if tunnel_mode is not None:
                logging.info('Restoring management interface for device %s'
                             % device['deviceid'])
                if device.get('external_ip') is not None:
                    device_external_ip = device['external_ip']
                if device.get('external_port') is not None:
                    device_external_port = device['external_port']
                if device.get('mgmt_mac') is not None:
                    device_vtep_mac = device['mgmt_mac']
                if device.get('vxlan_port') is not None:
                    vxlan_port = device['vxlan_port']
                # Create tunnel controller endpoint
                tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
                res, controller_vtep_mac, controller_vtep_ip, device_vtep_ip, \
                    vtep_mask = tunnel_mode.create_tunnel_controller_endpoint(
                        deviceid=deviceid,
                        tenantid=tenantid,
                        device_external_ip=device_external_ip,
                        device_external_port=device_external_port,
                        vxlan_port=vxlan_port,
                        device_vtep_mac=device_vtep_mac
                    )
                if res != STATUS_SUCCESS:
                    logging.warning('Cannot restore the tunnel on device %s'
                                    % deviceid)
                    return res
        # Success
        return STATUS_SUCCESS

    # Authenticate a device
    def authenticate_device(self, deviceid, auth_data):
        logging.info('Authenticating the device %s' % deviceid)
        # Get token
        token = auth_data.token
        # Authenticate the device
        authenticated, tenantid = (srv6_sdn_controller_state
                                   .authenticate_device(token))
        if not authenticated:
            return False, None
        # Return the tenant ID
        return True, tenantid

    # Register a device
    def register_device(self, deviceid, features,
                        interfaces, mgmtip, auth_data, sid_prefix=None,
                        public_prefix_length=None, enable_proxy_ndp=True):
        logging.info('Registering the device %s' % deviceid)
        # Device authentication
        authenticated, tenantid = self.authenticate_device(
            deviceid, auth_data)
        if not authenticated:
            logging.info('Authentication failed for the device %s' % deviceid)
            return STATUS_UNAUTHORIZED, None, None
        # If the device is already registered, send it the configuration
        # and create tunnels
        if srv6_sdn_controller_state.device_exists(deviceid, tenantid):
            logging.warning('The device %s is already registered' % deviceid)
            # TODO configure device
            # TODO create tunnels
        # Update controller state
        srv6_sdn_controller_state.register_device(
            deviceid, features, interfaces, mgmtip, tenantid, sid_prefix,
            public_prefix_length, enable_proxy_ndp)
        # Get the tenant configuration
        config = srv6_sdn_controller_state.get_tenant_config(tenantid)
        if config is None:
            logging.error(
                'Tenant not found or error while connecting to the db')
            return STATUS_INTERNAL_ERROR, None, None
        # Set the port
        vxlan_port = config.get('vxlan_port', DEFAULT_VXLAN_PORT)
        # Success
        logging.debug('New device registered:\n%s' % deviceid)
        return STATUS_SUCCESS, vxlan_port, tenantid

    # Update tunnel mode
    def update_mgmt_info(self, deviceid, tenantid, interfaces, mgmtip,
                         tunnel_name, nat_type,
                         device_external_ip, device_external_port,
                         device_vtep_mac, vxlan_port):
        logging.info('Updating the management information '
                     'for the device %s' % deviceid)
        # If a tunnel already exists, we need to destroy it
        # before creating the new tunnel
        old_tunnel_mode = srv6_sdn_controller_state.get_tunnel_mode(
            deviceid, tenantid)
        if old_tunnel_mode is not None:
            old_tunnel_mode = self.tunnel_state.tunnel_modes[old_tunnel_mode]
            res = old_tunnel_mode.destroy_tunnel_controller_endpoint(
                deviceid, tenantid)
            if res != status_codes_pb2.STATUS_SUCCESS:
                logging.error('Error during '
                              'destroy_tunnel_controller_endpoint')
                return res, None, None, None
            srv6_sdn_controller_state.set_tunnel_mode(deviceid, tenantid, None)
        # Get the tunnel mode requested by the device
        tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_name]
        # Create the tunnel
        logging.info('Trying to create the tunnel for the device %s'
                     % deviceid)
        res, controller_vtep_mac, controller_vtep_ip, device_vtep_ip, \
            vtep_mask = tunnel_mode.create_tunnel_controller_endpoint(
                deviceid=deviceid,
                tenantid=tenantid,
                device_external_ip=device_external_ip,
                device_external_port=device_external_port,
                vxlan_port=vxlan_port,
                device_vtep_mac=device_vtep_mac
            )
        if res != STATUS_SUCCESS:
            logging.warning('Cannot create the tunnel')
            return res, None, None, None
        # If a private IP address is present, use it as mgmt address
        res = srv6_sdn_controller_state.get_device_mgmtip(tenantid, deviceid)
        if res is not None:
            mgmtip = srv6_sdn_controller_state.get_device_mgmtip(
                tenantid, deviceid).split('/')[0]
        # Send a keep-alive messages to keep the tunnel opened,
        # if required for the tunnel mode
        # After N keep alive messages lost, we assume that the device
        # is not reachable, and we mark it as "not connected"
        if tunnel_mode.require_keep_alive_messages:
            Thread(target=utils.start_keep_alive_icmp, args=(
                mgmtip, self.keep_alive_interval, self.max_keep_alive_lost,
                None,
                lambda: self.device_disconnected(deviceid, tenantid)),
                daemon=False).start()
        # Update controller state
        srv6_sdn_controller_state.update_mgmt_info(
            deviceid, tenantid, mgmtip, interfaces, tunnel_name,
            nat_type, device_external_ip,
            device_external_port, device_vtep_mac, vxlan_port)
        # Mark the device as "connected"
        success = srv6_sdn_controller_state.set_device_connected_flag(
            deviceid=deviceid, tenantid=tenantid, connected=True)
        if success is None or success is False:
            err = ('Cannot set the device as connected. '
                   'Error while updating the controller state')
            logging.error(err)
            return STATUS_INTERNAL_ERROR
        # Success
        logging.debug('Updated management information: %s' % deviceid)
        return (STATUS_SUCCESS, controller_vtep_mac,
                controller_vtep_ip, device_vtep_ip, vtep_mask)

    def unregister_device(self, deviceid, tenantid):
        logging.debug('Unregistering the device %s' % deviceid)
        # Get the device
        device = srv6_sdn_controller_state.get_device(deviceid, tenantid)
        if device is None:
            logging.error('Device %s not found' % deviceid)
            return STATUS_INTERNAL_ERROR
        # Get tunnel mode
        tunnel_mode = device['tunnel_mode']
        if tunnel_mode is not None:
            # Get the tunnel mode class from its name
            tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
            # Destroy the tunnel
            logging.debug(
                'Trying to destroy the tunnel for the device %s' % deviceid)
            res = tunnel_mode.destroy_tunnel_controller_endpoint(
                deviceid, tenantid)
            if res != status_codes_pb2.STATUS_SUCCESS:
                logging.error('Error during '
                              'destroy_tunnel_controller_endpoint')
                return res
        # Success
        logging.debug('Device unregistered: %s' % deviceid)
        return STATUS_SUCCESS

    def device_disconnected(self, deviceid, tenantid):
        logging.debug('The device %s has been disconnected' % deviceid)
        # Get the device
        device = srv6_sdn_controller_state.get_device(deviceid, tenantid)
        if device is None:
            logging.error('Device %s not found' % deviceid)
            return STATUS_INTERNAL_ERROR
        # Mark the device as "not connected"
        success = srv6_sdn_controller_state.set_device_connected_flag(
            deviceid=deviceid, tenantid=tenantid, connected=False)
        if success is None or success is False:
            err = ('Cannot set the device as disconnected. '
                   'Error while updating the controller state')
            logging.error(err)
            return STATUS_INTERNAL_ERROR
        # Get tunnel mode
        tunnel_mode = device['tunnel_mode']
        if tunnel_mode is not None:
            # Get the tunnel mode class from its name
            tunnel_mode = self.tunnel_state.tunnel_modes[tunnel_mode]
            # Destroy the tunnel
            logging.debug(
                'Trying to destroy the tunnel for the device %s' % deviceid)
            res = tunnel_mode.destroy_tunnel_controller_endpoint(
                deviceid, tenantid)
            if res != status_codes_pb2.STATUS_SUCCESS:
                logging.error('Error during '
                              'destroy_tunnel_controller_endpoint')
                return res
            srv6_sdn_controller_state.set_tunnel_mode(deviceid, None)
        # Success
        logging.debug('Device disconnected: %s' % deviceid)
        return STATUS_SUCCESS

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
        # If secure mode is enabled, we need to create a secure endpoint
        if self.secure:
            # Read key and certificate
            with open(self.key, 'rb') as f:
                key = f.read()
            with open(self.certificate, 'rb') as f:
                certificate = f.read()
            # Create server SSL credentials
            grpc_server_credentials = grpc.ssl_server_credentials(
                ((key, certificate,),)
            )
            # Create a secure endpoint
            server.add_secure_port(
                server_address,
                grpc_server_credentials
            )
        else:
            # Create an insecure endpoint
            server.add_insecure_port(server_address)
        # Start the loop for gRPC
        logging.info('Server started: listening on %s' % server_address)
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
        '-a', '--keep-alive-interval', dest='keep_alive_interval',
        default=DEFAULT_KEEP_ALIVE_INTERVAL,
        help='Interval between two consecutive keep alive'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-m', '--max-keep-alive-lost', dest='max_keep_alive_lost',
        default=DEFAULT_MAX_KEEP_ALIVE_LOST,
        help='Interval between two consecutive keep alive'
    )
    # Server certificate file
    parser.add_argument(
        '-c', '--certificate', dest='certificate', action='store',
        default=DEFAULT_CERTIFICATE, help='Server certificate file'
    )
    # Server key
    parser.add_argument(
        '-k', '--key', dest='key', action='store',
        default=DEFAULT_KEY, help='Server key file'
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
    # Server certificate file
    certificate = args.certificate
    # Server key
    key = args.key
    # gRPC server IP
    server_ip = args.server_ip
    # gRPC server port
    server_port = args.server_port
    # Keep alive interval
    keep_alive_interval = args.keep_alive_interval
    # Max keep alive lost
    max_keep_alive_lost = args.max_keep_alive_lost
    # Start server
    controller = PymerangController(server_ip, server_port,
                                    keep_alive_interval,
                                    max_keep_alive_lost,
                                    secure, key, certificate)
    controller.serve()
