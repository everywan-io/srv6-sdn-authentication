#!/usr/bin/env python

# General imports
from __future__ import print_function
from argparse import ArgumentParser
from threading import Thread
from socket import AF_INET, AF_INET6
import logging
import pynat
import grpc
import json
import sys
import time
import errno
from datetime import datetime, timedelta
# ipaddress dependencies
from ipaddress import IPv4Address, IPv6Address
# pymerang dependencies
from pymerang import utils
from pymerang import pymerang_pb2
from pymerang import pymerang_pb2_grpc
from pymerang import status_codes_pb2
from pymerang import cert_authority_pb2
from pymerang import cert_authority_pb2_grpc
# SSL utils
from srv6_sdn_openssl import ssl


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
# Max number of keep alive messages lost
# before taking a corrective action
DEFAULT_MAX_KEEP_ALIVE_LOST = 3
# Source port of the NAT discovery
DEFAULT_VXLAN_PORT = 4789
# File containing the token
DEFAULT_TOKEN_FILE = 'token'
# Define wheter to use SSL or not
DEFAULT_SECURE = False
# SSL cerificate for server validation
DEFAULT_CERTIFICATE = 'cert_client.pem'
# GRPC retry interval (in seconds)
GRPC_RETRY_INTERVAL = 10
# Flag indicating if the device certificate
# needs to be generated dynamically
# (with a Certification Signing Request sent
# to a Certification Authority)
DYNAMICALLY_GENERATED_CERTIFICATE = False
# Filename of the server certificate
SERVER_CERT_FILENAME = 'server.crt'
# Filename of the server private key
SERVER_KEY_FILENAME = 'server.key'
# Renewal certificate before (in days)
RENEW_CERT_BEFORE = 1


class PymerangDevice:

    def __init__(self, server_ip, server_port,
                 ca_server_ip, ca_server_port, nat_discovery_server_ip,
                 nat_discovery_server_port, nat_discovery_client_ip,
                 nat_discovery_client_port, config_file, token_file,
                 keep_alive_interval=DEFAULT_KEEP_ALIVE_INTERVAL,
                 max_keep_alive_lost=DEFAULT_MAX_KEEP_ALIVE_LOST,
                 secure=DEFAULT_SECURE, certificate=DEFAULT_CERTIFICATE,
                 start_event=None, stop_event=None, restart_event=None,
                 debug=False):
        # Debug mode
        self.debug = debug
        # IP address of the gRPC server
        self.server_ip = server_ip
        # Port on which the gRPC server is listening
        self.server_port = server_port
        # IP address of the CA gRPC server
        self.ca_server_ip = ca_server_ip
        # Port on which the CA gRPC server is listening
        self.ca_server_port = ca_server_port
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
        self.deviceid = config['id']
        # Save the list of the supported features
        self.features = config.get('features', [])
        # Save interval between two consecutive keep alive messages
        self.keep_alive_interval = keep_alive_interval
        # Max keep alive lost
        self.max_keep_alive_lost = max_keep_alive_lost
        # Read the token from the token file
        with open(token_file, 'r') as token_file:
            # Save the token
            self.token = token_file.read()
            # Remove trailing new line character
            self.token = self.token.rstrip('\n')
        # IP address of the controller VTEP
        self.controller_vtep_ip = None
        # MAC address of the controller VTEP
        self.controller_vtep_mac = None
        # IP address of the device VTEP
        self.device_vtep_ip = None
        # MAC address of the device VTEP
        self.device_vtep_mac = None
        # Management IP addresses of the device
        self.device_mgmtips = set()
        # Tunnel state
        self.tunnel_state = None
        # Secure mode
        self.secure = secure
        if secure is True:
            if certificate is None:
                logging.error('Error: "certificate" variable cannot be None '
                              'in secure mode')
                sys.exit(-2)
            self.certificate = certificate
        # Filename of the server certificate
        self.server_cert_filename = SERVER_CERT_FILENAME
        # Filename of the server private key
        self.server_key_filename = SERVER_KEY_FILENAME
        # Interfaces on the device
        self.interfaces = list()
        # Flags indicating if the management interface has been configured
        self.tunnel_device_endpoint_configured = False
        self.tunnel_device_endpoint_end_configured = False
        # Start event. This flag is set when the PymerangDevice
        # initialization has been completed
        self.start_event = start_event
        # Stop event. If set, something has requested the termination of
        # the device and we need to deallocate the management interface
        # and gracefully shutdown this script
        self.stop_event = stop_event
        # Restart event. This flag is set when device modules require
        # to be restarted (e.g. a certificate expired and the southbound
        # server has to be restarted with the new certificate or the management
        # IP address has changed and the certificate has to be renewed)
        self.restart_event = restart_event
        # Start thread listening for device shutdown
        if stop_event is not None:
            Thread(target=self.shutdown_device).start()
        # Flag indicating whether the Pymerang Device
        # has been initialized or not
        self.initialized = False
        # Channel
        self.channel = None

    # Build a grpc stub
    def get_grpc_session(self, address, port):
        # Get the address of the server
        if utils.getAddressFamily(address) == AF_INET6:
            # IPv6 address
            server_address = '[%s]:%s' % (address, port)
        elif utils.getAddressFamily(address) == AF_INET:
            # IPv4 address
            server_address = '%s:%s' % (address, port)
        else:
            # Address is a hostname
            server_address = '%s:%s' % (address, port)
        # If no channel has been created yet, create a new one
        if self.channel is None:
            # If secure we need to establish a channel with the secure endpoint
            if self.secure:
                # Open the certificate file
                with open(self.certificate, 'rb') as f:
                    certificate = f.read()
                # Then create the SSL credentials and establish the channel
                grpc_client_credentials = grpc.ssl_channel_credentials(
                    certificate)
                self.channel = grpc.secure_channel(server_address,
                                                   grpc_client_credentials)
            else:
                self.channel = grpc.insecure_channel(server_address)
        return self.channel

    def run_nat_discovery(self):
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
        # Set the interfaces
        interfaces = utils.get_local_interfaces()
        for ifname, ifinfo in interfaces.items():
            # interface.ext_ipv6_addrs.extend(ifinfo['ipv6_addrs'])
            # interface.ext_ipv4_addrs.extend(ifinfo['ipv4_addrs'])
            ext_ipv4_addrs = list()
            ext_ipv6_addrs = list()
            if ifname != 'lo':
                for addr in ifinfo['ipv4_addrs']:
                    # Run the stun test to discover the
                    # external IP and port of the interface
                    addr = addr.split('/')[0]
                    if not IPv4Address(addr).is_link_local:
                        try:
                            nat_type, external_ip, external_port = \
                                pynat.get_ip_info(
                                    addr.split('/')[0],
                                    self.nat_discovery_client_port,
                                    self.nat_discovery_server_ip,
                                    self.nat_discovery_server_port
                                )
                            if external_ip is not None:
                                ext_ipv4_addrs.append(
                                    external_ip)
                            if nat_type == pynat.OPEN:
                                # This interface can be used for management
                                if external_ip != '':
                                    self.device_mgmtips.add(external_ip)
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
                                pynat.get_ip_info(
                                    addr.split('/')[0],
                                    self.nat_discovery_client_port,
                                    self.nat_discovery_server_ip,
                                    self.nat_discovery_server_port
                                )
                            if external_ip is not None:
                                ext_ipv6_addrs.append(
                                    external_ip)
                            if nat_type == pynat.OPEN:
                                # This interface can be used for management
                                if external_ip != '':
                                    self.device_mgmtips.add(external_ip)
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
            # Append the interface
            self.interfaces.append({
                'name': ifname,
                'ext_ipv4_addrs': ext_ipv4_addrs,
                'ext_ipv6_addrs': ext_ipv6_addrs
            })
        # Set the tunnel mode
        self.tunnel_mode = tunnel_mode

    def _register_device(self):
        # Establish a gRPC connection to the controller
        with self.get_grpc_session(self.server_ip,
                                   self.server_port) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            # Start registration procedure
            logging.info("-------------- RegisterDevice --------------")
            # Prepare the registration message
            request = pymerang_pb2.RegisterDeviceRequest()
            # Set the device ID
            request.device.id = self.deviceid
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
                # Store the tenant ID
                self.tenantid = response.tenantid
                # If no port has been specified for NAT discovery client
                if self.nat_discovery_client_port == 0:
                    if response.mgmt_info.vxlan_port is not None:
                        # We use the port set by the tenant for VXLAN port
                        # forwarding
                        self.nat_discovery_client_port = \
                            response.mgmt_info.vxlan_port
                    else:
                        # If no port has been configured for port forwarding,
                        # we use the default port of VXLAN, i.e. 4789
                        self.nat_discovery_client_port = DEFAULT_VXLAN_PORT
                # NAT traversal require that the same port is used both for
                # NAT discovery and communication
                self.vxlan_port = self.nat_discovery_client_port
                # Return the configuration
                logging.info("*** RegisterDevice completed\n\n")
                return status_codes_pb2.STATUS_SUCCESS
            elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
                # Authentication failed
                logging.warning('Authentication failed')
                return status_codes_pb2.STATUS_UNAUTHORIZED
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return response.status

    def _update_mgmt_info(self):
        # Establish a gRPC connection to the controller
        with self.get_grpc_session(self.server_ip,
                                   self.server_port) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            # Prepare the registration message
            request = pymerang_pb2.RegisterDeviceRequest()
            # Start registration procedure
            logging.info("-------------- Update Management Info --------------")
            # Add external IP addresses to the request
            for ifinfo in self.interfaces:
                interface = request.interfaces.add()
                interface.name = ifinfo['name']
                interface.ext_ipv4_addrs.extend(ifinfo['ext_ipv4_addrs'])
                interface.ext_ipv6_addrs.extend(ifinfo['ext_ipv6_addrs'])
            # Set the device ID
            request.device.id = self.deviceid
            # Set the tenant ID
            request.tenantid = self.tenantid
            # Set the token
            request.auth_data.token = self.token
            # Set the tunnel mode
            request.mgmt_info.tunnel_mode = self.tunnel_mode.name
            # Set the NAT type
            request.mgmt_info.nat_type = self.nat_type
            # Set the device external IP
            request.mgmt_info.device_external_ip = self.external_ip
            # Set the device external port
            request.mgmt_info.device_external_port = self.external_port
            # Set the VXLAN port
            request.mgmt_info.vxlan_port = self.vxlan_port
            # Destroy old management interfaces, before creating the new one
            if self.tunnel_device_endpoint_end_configured:
                # Management interface already configured
                # We need to destroy it before creating a new one
                res = self.tunnel_mode.destroy_tunnel_device_endpoint_end(
                    self.deviceid, self.tenantid,
                    self.controller_vtep_ip, self.controller_vtep_mac)
                if res != status_codes_pb2.STATUS_SUCCESS:
                    logging.error('Cannot destroy the management interface')
                    return res
                self.tunnel_device_endpoint_end_configured = False
            # if self.tunnel_device_endpoint_configured:
            #     # Management interface already configured
            #     # We need to destroy it before creating a new one
            #     res = self.tunnel_mode.destroy_tunnel_device_endpoint(
            #         self.deviceid, self.tenantid)
            #     if res != status_codes_pb2.STATUS_SUCCESS:
            #         logging.error('Cannot destroy the management interface')
            #         return res
            #     self.tunnel_device_endpoint_configured = False
            # Create the tunnel
            if not self.tunnel_device_endpoint_configured:
                logging.info('Creating the tunnel for the device')
                res, self.device_vtep_mac = \
                    self.tunnel_mode.create_tunnel_device_endpoint(
                        deviceid=self.deviceid,
                        tenantid=self.tenantid,
                        vxlan_port=self.vxlan_port,
                    )
                if res != status_codes_pb2.STATUS_SUCCESS:
                    logging.error('Cannot create the management interface')
                    return res
                self.tunnel_device_endpoint_configured = True
            # Set the MAC address of the device's VTEP
            if self.device_vtep_mac is not None:
                request.mgmt_info.device_vtep_mac = self.device_vtep_mac
            # Send the update tunnel mode request
            logging.info('Sending the update tunnel mode request')
            response = stub.UpdateMgmtInfo(request)
            if response.status == status_codes_pb2.STATUS_SUCCESS:
                # Extract IP address of the controller's VTEP
                self.controller_vtep_ip = response.mgmt_info.controller_vtep_ip
                # Extract IP address of the device's VTEP
                self.device_vtep_ip = response.mgmt_info.device_vtep_ip
                if self.device_vtep_ip is not None and \
                        self.device_vtep_ip != '':
                    self.device_mgmtips.add(self.device_vtep_ip)
                # Extract mask of the VTEP
                vtep_mask = response.mgmt_info.vtep_mask
                # Extract MAC address of the controller's VTEP
                self.controller_vtep_mac = (response.mgmt_info
                                            .controller_vtep_mac)
                # Create the tunnel
                logging.info('Finalizing tunnel configuration')
                res = self.tunnel_mode.create_tunnel_device_endpoint_end(
                    deviceid=self.deviceid,
                    tenantid=self.tenantid,
                    controller_vtep_ip=self.controller_vtep_ip,
                    device_vtep_ip=self.device_vtep_ip, vtep_mask=vtep_mask,
                    controller_vtep_mac=self.controller_vtep_mac
                )
                if res != status_codes_pb2.STATUS_SUCCESS:
                    logging.error('Cannot create the management interface')
                    return res
                self.tunnel_device_endpoint_end_configured = True
                # Get the controller address
                self.controller_mgmtip = \
                    self.tunnel_mode.get_controller_mgmtip()
                if self.controller_mgmtip is None:
                    # If the tunnel mode does not specifies any mgmt IP
                    # for the controller we use the public IP address
                    self.controller_mgmtip = self.server_ip
                # Send a keep-alive messages to keep the tunnel opened,
                # if required
                if self.tunnel_mode.require_keep_alive_messages:
                    Thread(target=utils.start_keep_alive_icmp,
                           args=(self.controller_mgmtip,
                                 self.keep_alive_interval,
                                 self.max_keep_alive_lost,
                                 self.stop_event,
                                 self.restart_event,
                                 self.secure_update_mgmt_info
                                 ),
                           daemon=False
                           ).start()
                # Return the configuration
                logging.info("*** Update Management Info completed\n\n")
                return status_codes_pb2.STATUS_SUCCESS
            elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
                # Authentication failed
                logging.warning('Authentication failed')
                return status_codes_pb2.STATUS_UNAUTHORIZED
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return response.status

    def _sign_certificate(self, deviceid, ip_addresses):
        # Establish a gRPC connection to the controller
        with self.get_grpc_session(self.ca_server_ip,
                                   self.ca_server_port) as channel:
            # Get the stub
            stub = cert_authority_pb2_grpc.CertAuthorityStub(channel)
            # Prepare the request message
            request = cert_authority_pb2.SignCertificateRequest()
            # Start certificate signing
            logging.info("-------------- Sign SSL Certificate --------------")
            # Generate a Certification Signing Request
            csr, key = ssl.generate_csr(deviceid, ip_addresses)
            # Add CSR to the gRPC request
            request.csr = csr
            # Set the device ID
            request.device.id = self.deviceid
            # Set the token
            request.auth_data.token = self.token
            # Send the update tunnel mode request
            logging.info('Sending the Certificate Signing Request')
            response = stub.SignCertificate(request)
            if response.status == status_codes_pb2.STATUS_SUCCESS:
                # Extract the certificate signed by the CA
                cert = response.cert
                # Save the certificate to file
                ssl.save_to_file(cert, self.server_cert_filename)
                # Save the private key to file
                ssl.save_to_file(key, self.server_key_filename)
                # Return the configuration
                logging.info("*** Sign SSL Certificate completed\n\n")
                return status_codes_pb2.STATUS_SUCCESS
            elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
                # Authentication failed
                logging.warning('Authentication failed')
                return status_codes_pb2.STATUS_UNAUTHORIZED
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return response.status

    def update_mgmt_info(self):
        while True:
            try:
                # Try to update tunnel mode
                return self._update_mgmt_info()
            except grpc.RpcError as e:
                status_code = e.code()
                details = e.details()
                if grpc.StatusCode.UNAVAILABLE == status_code:
                    # If the controller is not reachable,
                    # retry after X seconds
                    logging.error('Unable to contact controller '
                                  '(unreachable gRPC server): %s\n\n'
                                  'Retrying in %s seconds'
                                  % (details, GRPC_RETRY_INTERVAL))
                    time.sleep(GRPC_RETRY_INTERVAL)
                else:
                    logging.error('Error in update_mgmt_info: '
                                  '%s - %s' % (status_code, details))
                    return status_codes_pb2.STATUS_INTERNAL_ERROR

    def register_device(self):
        while True:
            try:
                # Try to register device
                return self._register_device()
            except grpc.RpcError as e:
                status_code = e.code()
                details = e.details()
                if grpc.StatusCode.UNAVAILABLE == status_code:
                    # If the controller is not reachable,
                    # retry after X seconds
                    logging.error('Unable to contact controller '
                                  '(unreachable gRPC server): %s\n\n'
                                  'Retrying in %s seconds'
                                  % (details, GRPC_RETRY_INTERVAL))
                    time.sleep(GRPC_RETRY_INTERVAL)
                else:
                    logging.error('Error in update_mgmt_info: '
                                  '%s - %s' % (status_code, details))
                    return status_codes_pb2.STATUS_INTERNAL_ERROR

    def secure_update_mgmt_info(self):
        # Update managment interface
        res = self.update_mgmt_info()
        if res != status_codes_pb2.STATUS_SUCCESS:
            return res
        # Sign certificate, if the secure mode is enabled
        if DYNAMICALLY_GENERATED_CERTIFICATE:
            if self.secure:
                res = self.sign_certificate(self.deviceid, self.device_mgmtips)
                if res != status_codes_pb2.STATUS_SUCCESS:
                    return res
            if self.initialized:
                # Already initialized, this is a restart
                if self.restart_event is not None:
                    self.restart_event.set()
                # Stop the gRPC server
                # It is restarted automatically, since we
                # have set the restart_event flag
                if self.stop_event is not None:
                    self.stop_event.set()
        # Return
        return res

    def shutdown_device(self):
        # Wait until a termination signal is received
        while True:
            self.stop_event.wait()
            if not self.restart_event.is_set():
                # Restart event is not set
                # Termination
                break
        # Received termination signal
        logging.info('Received shutdown command. '
                     'Destroying management interface')
        # Remove the management interface
        res = self.tunnel_mode.destroy_tunnel_device_endpoint_end(
            self.deviceid, self.tenantid,
            self.controller_vtep_ip, self.controller_vtep_mac)
        if res != status_codes_pb2.STATUS_SUCCESS:
            logging.error('Error during '
                          'destroy_tunnel_device_endpoint_end')
            return res
        self.tunnel_device_endpoint_end_configured = False
        res = self.tunnel_mode.destroy_tunnel_device_endpoint(
            self.deviceid, self.tenantid)
        if res != status_codes_pb2.STATUS_SUCCESS:
            logging.error('Error during '
                          'destroy_tunnel_device_endpoint_end')
            return res
        self.tunnel_device_endpoint_configured = False
        logging.info('Management interface destroyed')
        return status_codes_pb2.STATUS_SUCCESS

    def sign_certificate(self, deviceid, ip_addresses):
        while True:
            try:
                # Try to get a certificate from the CA
                return self._sign_certificate(deviceid, ip_addresses)
            except grpc.RpcError as e:
                status_code = e.code()
                details = e.details()
                if grpc.StatusCode.UNAVAILABLE == status_code:
                    # If the controller is not reachable,
                    # retry after X seconds
                    logging.error('Unable to contact controller '
                                  '(unreachable gRPC server): %s\n\n'
                                  'Retrying in %s seconds'
                                  % (details, GRPC_RETRY_INTERVAL))
                    time.sleep(GRPC_RETRY_INTERVAL)
                else:
                    logging.error('Error in sign_certificate(): '
                                  '%s - %s' % (status_code, details))
                    return status_codes_pb2.STATUS_INTERNAL_ERROR

    def validate_cert(self, cert_filename):
        # Validate a certificate
        try:
            with open(cert_filename, 'rb') as cert:
                cert = cert.read()
                return ssl.validate_cert(cert)
        except IOError as e:
            if e.errno == errno.ENOENT:
                logging.info('Certificate not found')
                return False

    def _download_cert(self):
        # Establish a gRPC connection to the controller
        with self.get_grpc_session(self.server_ip,
                                   self.server_port) as channel:
            # Get the stub
            stub = pymerang_pb2_grpc.PymerangStub(channel)
            # Start registration procedure
            logging.info("-------------- DownloadCertificate --------------")
            # Prepare the registration message
            request = pymerang_pb2.DownloadCertificateRequest()
            # Set the device ID
            request.deviceid = self.deviceid
            # Set the token
            request.auth_data.token = self.token
            # Set the tenant ID
            request.tenantid = self.tenantid
            # Send the download certificate request
            logging.info('Sending the download certificate request')
            response = stub.DownloadCertificate(request)
            if response.status == status_codes_pb2.STATUS_SUCCESS:
                logging.info('Certificate download completed')
                # Extract the certificate signed by the CA
                cert = response.cert
                # Extract the private key
                key = response.key
                # Save the certificate to file
                ssl.save_to_file(cert, 'server.crt')
                # Save the private key to file
                ssl.save_to_file(key, 'server.key')
                logging.info("*** DownloadCertificate completed\n\n")
                return status_codes_pb2.STATUS_SUCCESS
            elif response.status == status_codes_pb2.STATUS_UNAUTHORIZED:
                # Authentication failed
                logging.warning('Authentication failed')
                return status_codes_pb2.STATUS_UNAUTHORIZED
            else:
                # Unknown status code
                logging.warning('Unknown status code: %s' % response.status)
                return response.status

    def download_cert(self):
        while True:
            try:
                # Try to get a certificate from the CA
                return self._download_cert()
            except grpc.RpcError as e:
                status_code = e.code()
                details = e.details()
                if grpc.StatusCode.UNAVAILABLE == status_code:
                    # If the controller is not reachable,
                    # retry after X seconds
                    logging.error('Unable to contact controller '
                                  '(unreachable gRPC server): %s\n\n'
                                  'Retrying in %s seconds'
                                  % (details, GRPC_RETRY_INTERVAL))
                    time.sleep(GRPC_RETRY_INTERVAL)
                else:
                    logging.error('Error in download_cert(): '
                                  '%s - %s' % (status_code, details))
                    return status_codes_pb2.STATUS_INTERNAL_ERROR

    def manage_certificate(self):
        if not self.validate_cert(self.server_cert_filename):
            # Certificate is not valid
            # Download a new certificate from the controller
            logging.info('Certificate not found or expired')
            while True:
                logging.info('Downloading a new certificate')
                if self.download_cert() == status_codes_pb2.STATUS_SUCCESS:
                    break
                logging.warning('Error in download certificate. Retrying...')
                time.sleep(3)
            logging.info('Certificate downloaded successfully')
        else:
            logging.info('Found a valid certificate: %s'
                         % self.server_cert_filename)
        while True:
            with open(self.server_cert_filename, 'rb') as server_cert:
                server_cert = server_cert.read()
            # Get the certificate expiration
            expiration = ssl.get_cert_expiration(server_cert)
            # Wait until the next expiration
            logging.info('Certificate expires on %s' % expiration)
            # Establish when the certificate has to be renewed
            renewal_cert_datetime = expiration - timedelta(
                days=RENEW_CERT_BEFORE)
            # Current datetime
            now = datetime.utcnow()
            time.sleep((renewal_cert_datetime - now).seconds)
            logging.info('The certificate of the gRPC server is expiring soon')
            # Download a new certificate
            while True:
                logging.info('Downloading a new certificate')
                if self.download_cert() == status_codes_pb2.STATUS_SUCCESS:
                    break
                logging.warning('Error in download certificate. Retrying...')
                time.sleep(3)
            logging.info('Certificate downloaded successfully')
            # Check if the gRPC has to be restarted
            if self.initialized:
                # Already initialized, this is a restart
                if self.restart_event is not None:
                    self.restart_event.set()
                # Stop the gRPC server
                # It is restarted automatically, since we
                # have set the restart_event flag
                if self.stop_event is not None:
                    self.stop_event.set()

    def run(self):
        logging.info('Client started')
        # Initialize tunnel state
        self.tunnel_state = utils.TunnelState(self.server_ip, self.debug)
        # Register the device
        if self.register_device() != status_codes_pb2.STATUS_SUCCESS:
            logging.warning('Error in device registration')
            return status_codes_pb2.STATUS_INTERNAL_ERROR
        # Download a certificate for the gRPC server
        if not DYNAMICALLY_GENERATED_CERTIFICATE:
            # Download certificate and schedule renewal instants
            Thread(target=self.manage_certificate).start()
        # Start NAT discovery procedure
        self.run_nat_discovery()
        # Update tunnel mode
        if self.secure_update_mgmt_info() != \
                status_codes_pb2.STATUS_SUCCESS:
            logging.warning('Error in update tunnel mode')
            return status_codes_pb2.STATUS_INTERNAL_ERROR
        # Device initialization completed
        logging.info('*** Device authentication and registration completed ***'
                     '\n\n\n')
        if self.start_event is not None:
            self.start_event.set()
        self.initialized = True


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
    # IP address of the certification authority
    parser.add_argument(
        '--ca-server-ip', dest='ca_server_ip',
        default=DEFAULT_PYMERANG_SERVER_IP,
        help='Certification authority server IP address'
    )
    # Port of the gRPC server on the certification authority
    parser.add_argument(
        '--ca-server-port', dest='ca_server_port',
        default=DEFAULT_PYMERANG_SERVER_PORT,
        help='Certification authority server port'
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
        '-f', '--config-file', dest='config_file',
        default=DEFAULT_CONFIG_FILE, help='Config file'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-a', '--keep-alive-interval', dest='keep_alive_interval',
        default=DEFAULT_KEEP_ALIVE_INTERVAL,
        help='Interval between two consecutive keep alive'
    )
    # Max keep alive lost
    parser.add_argument(
        '-x', '--max-keep-alive-lost', dest='max_keep_alive_lost',
        default=DEFAULT_MAX_KEEP_ALIVE_LOST,
        help='Max keep alive lost'
    )
    # Interval between two consecutive keep alive messages
    parser.add_argument(
        '-t', '--token-file', dest='token_file',
        default=DEFAULT_TOKEN_FILE,
        help='File containing the token used for the authentication'
    )
    # Server certificate file
    parser.add_argument(
        '-c', '--certificate', dest='certificate', action='store',
        default=DEFAULT_CERTIFICATE, help='Server certificate file'
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
    # Server certificate file
    certificate = args.certificate
    # Server IP
    server_ip = args.server_ip
    # Server port
    server_port = args.server_port
    # CA Server IP
    ca_server_ip = args.ca_server_ip
    # CA Server port
    ca_server_port = args.ca_server_port
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
    # Max keep alive lost
    max_keep_alive_lost = args.max_keep_alive_lost
    # File containing the token used for the authentication
    token_file = args.token_file
    # Start client
    client = PymerangDevice(
        server_ip=server_ip,
        server_port=server_port,
        ca_server_ip=ca_server_ip,
        ca_server_port=ca_server_port,
        nat_discovery_server_ip=nat_discovery_server_ip,
        nat_discovery_server_port=nat_discovery_server_port,
        nat_discovery_client_ip=nat_discovery_client_ip,
        nat_discovery_client_port=nat_discovery_client_port,
        config_file=config_file,
        token_file=token_file,
        keep_alive_interval=keep_alive_interval,
        max_keep_alive_lost=max_keep_alive_lost,
        start_event=None,
        stop_event=None,
        restart_event=None,
        debug=debug)
    client.run()
