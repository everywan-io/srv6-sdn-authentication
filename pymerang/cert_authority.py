#!/usr/bin/env python

# General imports
from argparse import ArgumentParser
from concurrent import futures
from socket import AF_INET, AF_INET6
import logging
import time
import grpc
# pymerang dependencies
from pymerang import tunnel_utils
from pymerang import cert_authority_pb2
from pymerang import cert_authority_pb2_grpc
from pymerang import status_codes_pb2
# SRv6 dependencies
from srv6_sdn_controller_state import srv6_sdn_controller_state
# SSL utils
from srv6_sdn_openssl import ssl


# Loopback IP address of the controller
DEFAULT_PYMERANG_SERVER_IP = '::'
# Port of the gRPC server executing on the controller
DEFAULT_PYMERANG_SERVER_PORT = 50061
# Secure option
DEFAULT_SECURE = False
# Server certificate
DEFAULT_CERTIFICATE = 'cert_server.pem'
# Server key
DEFAULT_KEY = 'key_server.pem'
# Certificates expire after X days
CERT_EXPIRES_AFTER = 3 * 365

# Status codes
STATUS_SUCCESS = status_codes_pb2.STATUS_SUCCESS
STATUS_UNAUTHORIZED = status_codes_pb2.STATUS_UNAUTHORIZED
STATUS_INTERNAL_ERROR = status_codes_pb2.STATUS_INTERNAL_ERROR


class CertAuthorityServicer(cert_authority_pb2_grpc.CertAuthorityServicer):
    """Provides methods that implement functionality of route guide server."""

    def __init__(self, ca_cert):
        # Store the CA certificate
        self.ca_cert = ca_cert

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

    def SignCertificate(self, request, context):
        logging.info('Sign certificate request received: %s' % request)
        # Extract the parameters from the request
        #
        # Device ID
        deviceid = request.device.id
        # Certificate Signing Request
        csr = request.csr
        # Authentication data
        auth_data = request.auth_data
        # Authenticate the device
        authenticated, tenantid = self.authenticate_device(
            deviceid, auth_data)
        if not authenticated:
            logging.info('Authentication failed for the device %s' % deviceid)
            return cert_authority_pb2.SignCertificateReply(
                status=STATUS_UNAUTHORIZED)
        # Get the CA certificate
        with open(self.ca_cert, 'rb') as f:
            certificate = f.read()
        # Sign the certificate
        cert, key = ssl.generate_cert(
            csr, certificate, expires_after=CERT_EXPIRES_AFTER)
        # Create the response
        reply = cert_authority_pb2.SignCertificateReply()
        # Set the status code
        reply.status = STATUS_SUCCESS
        # Add the certificate to the response
        reply.cert = cert
        # Send the reply
        logging.info('Sending the reply: %s' % reply)
        return reply


def start_server(server_ip, server_port,
                 secure, ca_key, ca_cert):
    # Start gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    cert_authority_pb2_grpc.add_CertAuthorityServicer_to_server(
        CertAuthorityServicer(ca_cert), server
    )
    if tunnel_utils.getAddressFamily(server_ip) == AF_INET6:
        server_address = '[%s]:%s' % (server_ip, server_port)
    elif tunnel_utils.getAddressFamily(server_ip) == AF_INET:
        server_address = '%s:%s' % (server_ip, server_port)
    else:
        logging.error('Invalid server address %s' % server_ip)
        return
    # If secure mode is enabled, we need to create a secure endpoint
    if secure:
        # Read key and certificate
        with open(ca_key, 'rb') as f:
            key = f.read()
        with open(ca_cert, 'rb') as f:
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
    # Server certificate file
    parser.add_argument(
        '-c', '--ca-cert', dest='ca_cert', action='store',
        default=DEFAULT_CERTIFICATE, help='CA certificate file'
    )
    # Server key
    parser.add_argument(
        '-k', '--ca-key', dest='ca_key', action='store',
        default=DEFAULT_KEY, help='CA key file'
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
    # CA certificate file
    ca_cert = args.ca_cert
    # CA key
    ca_key = args.ca_key
    # gRPC server IP
    server_ip = args.server_ip
    # gRPC server port
    server_port = args.server_port
    # Start server
    start_server(
        server_ip=server_ip,
        server_port=server_port,
        secure=secure,
        ca_key=ca_key,
        ca_cert=ca_cert
    )
