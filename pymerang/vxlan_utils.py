#!/usr/bin/env python

# General imports
import pyroute2
import logging
import socket
import pynat
# pyroute2 dependencies
from pyroute2 import IPRoute
# pymerang dependencies
from pymerang import tunnel_utils
from pymerang import status_codes_pb2
try:
    from srv6_sdn_controller_state import srv6_sdn_controller_state
except ModuleNotFoundError:
    logging.warn('srv6_sdn_controller_state module not found.\n'
                 'This module is required only for the controller.\n'
                 'If you are executing the EveryEdge software, you can '
                 'safely ignore this warning.')


# Global variables
NO_SUCH_FILE_OR_DIRECTORY = 2
# Destination port used by VXLAN interfaces
VXLAN_DSTPORT = 4789
# Enable UDP checksum on VXLAN packets
ENABLE_UDP_CSUM = False
# VNI used for the management VTEPs
MGMT_VNI = 0


def create_vxlan(device, vni, phys_dev=None, remote=None,
                 local=None, remote6=None, local6=None,
                 ttl=None, tos=None, flowlabel=None,
                 dstport=None, srcport_min=None,
                 srcport_max=None, learning=None, proxy=None,
                 rsc=None, l2miss=None, l3miss=None,
                 udpcsum=None, udp6zerocsumtx=None,
                 udp6zerocsumrx=None, ageing=None,
                 gbp=None, gpe=None):
    '''
    From the Manpage:

    ip link add DEVICE type vxlan id VNI [ dev PHYS_DEV ] [ { group |
    remote } IPADDR ] [ local { IPADDR | any } ] [ ttl TTL ] [ tos TOS ]
    [ flowlabel FLOWLABEL ] [ dstport PORT ] [ srcport MIN MAX ] [
    [no]learning ] [ [no]proxy ] [ [no]rsc ] [ [no]l2miss ] [ [no]l3miss
    ] [ [no]udpcsum ] [ [no]udp6zerocsumtx ] [ [no]udp6zerocsumrx ] [
    ageing SECONDS ] [ maxaddress NUMBER ] [ [no]external ] [ gbp ] [ gpe
    ]
    '''
    # Get pyroute2 instance
    with IPRoute() as ip_route:
        # Get the interface index
        if phys_dev is not None:
            ifindex = ip_route.link_lookup(ifname=phys_dev)[0]
        else:
            ifindex = None
        # Create the link
        ip_route.link("add",
                      ifname=device,
                      kind="vxlan",
                      vxlan_id=vni,
                      vxlan_link=ifindex,
                      vxlan_group=remote,
                      vxlan_local=local,
                      vxlan_group6=remote6,
                      vxlan_local6=local6,
                      vxlan_ttl=ttl,
                      vxlan_tos=tos,
                      vxlan_label=flowlabel,
                      vxlan_port=dstport,
                      vxlan_port_range={
                          'low': srcport_min, 'high': srcport_max},
                      vxlan_learning=learning,
                      vxlan_proxy=proxy,
                      vxlan_rsc=rsc,
                      vxlan_l2miss=l2miss,
                      vxlan_l3miss=l3miss,
                      vxlan_udp_csum=udpcsum,
                      vxlan_udp_zero_csum6_tx=udp6zerocsumtx,
                      vxlan_udp_zero_csum6_rx=udp6zerocsumrx,
                      vxlan_ageing=ageing,
                      vxlan_gbp=gbp,
                      vxlan_gpe=gpe
                      )


def create_fdb_entry(dst, lladdr, dev, port=VXLAN_DSTPORT):
    # Get pyroute2 instance
    with IPRoute() as ip_route:
        # Replace the entry
        ip_route.fdb('add',
                     ifindex=ip_route.link_lookup(ifname=dev)[0],
                     lladdr=lladdr,
                     dst=dst,
                     port=port)


def update_fdb_entry(dst, lladdr, dev):
    # Get pyroute2 instance
    with IPRoute() as ip_route:
        # Replace the entry
        ip_route.fdb('replace',
                     ifindex=ip_route.link_lookup(ifname=dev)[0],
                     lladdr=lladdr,
                     dst=dst)


def remove_fdb_entry(lladdr, dev):
    # Get pyroute2 instance
    with IPRoute() as ip_route:
        # Remove the entry
        ip_route.fdb('del',
                     ifindex=ip_route.link_lookup(ifname=dev)[0],
                     lladdr=lladdr)


class TunnelVXLAN(tunnel_utils.TunnelMode):

    ''' VXLAN tunnel mode '''

    def __init__(self, name, priority, controller_ip, debug=False):
        # VXLAN tunnel mode requires to exchange keep alive
        # messages to keep the tunnel open
        req_keep_alive_messages = True
        # NAT types supported by the VXLAN tunnel mode
        supported_nat_types = [
            pynat.OPEN,
            pynat.FULL_CONE,
            pynat.RESTRICTED_CONE,
            pynat.RESTRICTED_PORT
        ]
        # Initiated flag used by the controller
        self.initiated = False
        # Create tunnel mode
        super().__init__(name=name,
                         require_keep_alive_messages=req_keep_alive_messages,
                         supported_nat_types=supported_nat_types,
                         priority=priority,
                         controller_ip=controller_ip,
                         debug=debug)

    def create_tunnel_device_endpoint(self, deviceid, tenantid, vxlan_port):
        logging.info('Creating the VXLAN management interface')
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        logging.debug('Attempting to create the VXLAN '
                      'interface %s with VNI %s' % (vxlan_name, vni))
        create_vxlan(device=vxlan_name, vni=vni,
                     dstport=vxlan_port, srcport_min=vxlan_port,
                     srcport_max=vxlan_port+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM,
                     learning=False)
        # Bring the interface UP
        logging.debug('Bringing the interface %s up' % vxlan_name)
        tunnel_utils.enable_interface(device=vxlan_name)
        # Include the VTEP's MAC address in the registration request
        # sent to the controller
        # The VTEP's MAC address is used to setup
        # the FDB entry on the controller side
        device_vtep_mac = tunnel_utils.get_mac_address(
            ifname=vxlan_name)
        # Success
        logging.debug('The VXLAN interface has been created')
        # (status_code, device_vtep_mac)
        return status_codes_pb2.STATUS_SUCCESS, device_vtep_mac

    def create_tunnel_device_endpoint_end(self, deviceid, tenantid,
                                          controller_vtep_ip,
                                          device_vtep_ip, vtep_mask,
                                          controller_vtep_mac):
        logging.info('Configuring the VXLAN management interface')
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Add a private address to the interface
        vxlan_name = '%s-%s' % (self.name, vni)
        logging.debug('Attempting to assign the IP address %s/%s '
                      'to the VXLAN management interface %s'
                      % (device_vtep_ip, vtep_mask, vxlan_name))
        tunnel_utils.add_address(device=vxlan_name,
                                 address=device_vtep_ip,
                                 mask=vtep_mask)
        # Create a FDB entry that associate the VTEP MAC address
        # to the controller IP address
        logging.debug('Attempting to add the entry to the FDB\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s'
                      % (self.controller_ip, controller_vtep_mac, vxlan_name))
        create_fdb_entry(dev=vxlan_name, lladdr=controller_vtep_mac,
                         dst=self.controller_ip)
        # Create a IP neighbor entry that associate the VTEP IP address
        # of the controller to the VTEP MAC address
        logging.debug('Attempting to add the neigh to the neigh table\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s'
                      % (controller_vtep_ip, controller_vtep_mac, vxlan_name))
        tunnel_utils.create_ip_neigh(dev=vxlan_name,
                                     lladdr=controller_vtep_mac,
                                     dst=controller_vtep_ip)
        # Save the VTEP IP addresses
        self.controller_mgmtip = controller_vtep_ip
        self.device_vtep_ip = device_vtep_ip
        self.vtep_mask = vtep_mask
        # Success
        logging.debug('The VXLAN interface has been configured')
        # (status_code, device_vtep_mac)
        return status_codes_pb2.STATUS_SUCCESS

    def create_tunnel_controller_endpoint(self, deviceid, tenantid,
                                          device_external_ip,
                                          device_external_port,
                                          vxlan_port,
                                          device_vtep_mac):
        logging.info('Configuring the VXLAN tunnel for the device %s'
                     % deviceid)
        # Extract the tenant ID
        #tenantid = tunnel_info.tenantid
        _tenantid = '0'
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Save the MAC address of the device's VTEP
        srv6_sdn_controller_state.update_device_vtep_mac(
            deviceid, tenantid, device_vtep_mac)
        # Init VXLAN tunnel mode
        if not self.initiated:
            self.init_tunnel_controller_endpoint()
            self.initiated = True
        # Generate private address for the device VTEP
        family = tunnel_utils.getAddressFamily(device_external_ip)
        if family == socket.AF_INET6:
            ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv6(
                '0').split('/')
            controller_vtep_ip = ip_mask[0]
            ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv6(
                deviceid).split('/')
            device_vtep_ip = ip_mask[0]
            vtep_mask = int(ip_mask[1])
        elif family == socket.AF_INET:
            ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv4(
                '0').split('/')
            controller_vtep_ip = ip_mask[0]
            ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv4(
                deviceid).split('/')
            device_vtep_ip = ip_mask[0]
            vtep_mask = int(ip_mask[1])
        else:
            logging.error('Invalid family address: %s' %
                          device_external_ip)
            # (status_code, controller_vtep_mac,
            #      controller_vtep_ip, device_vtep_ip, vtep_mask)
            return (status_codes_pb2.STATUS_INTERNAL_ERROR,
                    None, None, None, None)
        # Create a FDB entry that associate the device VTEP MAC address
        # to the device IP address
        logging.debug('Attempting to add the entry to the FDB\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s, port=%s'
                      % (device_external_ip, device_vtep_mac,
                         vxlan_name, device_external_port))
        create_fdb_entry(dev=vxlan_name, lladdr=device_vtep_mac,
                         dst=device_external_ip, port=device_external_port)
        # Create a IP neighbor entry that associate the VTEP IP address
        # of the device to the device VTEP MAC address
        logging.debug('Attempting to add the neigh to the neigh table\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s'
                      % (device_vtep_ip, device_vtep_mac, vxlan_name))
        tunnel_utils.create_ip_neigh(dev=vxlan_name, lladdr=device_vtep_mac,
                                     dst=device_vtep_ip)
        # Update and return the tunnel info
        controller_vtep_mac = tunnel_utils.get_mac_address(
            ifname=vxlan_name)
        # Update device VTEP IP address
        success = srv6_sdn_controller_state.update_device_vtep_ip(
            deviceid, tenantid, device_vtep_ip)
        if success is not True:
            logging.error('Error while updating device VTEP IP address')
            # (status_code, controller_vtep_mac,
            #      controller_vtep_ip, device_vtep_ip, vtep_mask)
            return (status_codes_pb2.STATUS_INTERNAL_ERROR,
                    None, None, None, None)
        # Success
        logging.debug('The VXLAN interface has been configured')
        # (status_code, controller_vtep_mac,
        #      controller_vtep_ip, device_vtep_ip, vtep_mask)
        return (status_codes_pb2.STATUS_SUCCESS, controller_vtep_mac,
                controller_vtep_ip, device_vtep_ip, vtep_mask)

    def destroy_tunnel_device_endpoint_end(self, deviceid, tenantid,
                                           controller_vtep_ip,
                                           controller_vtep_mac):
        logging.info('Destroying the VXLAN tunnel '
                     '(destroy_tunnel_device_endpoint_end)')
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Name of the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Remove the IP neighbor entry that associates the VTEP IP address
        # of the controller to the VTEP MAC address
        logging.debug('Attempting to remove the neigh from the neigh table\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s'
                      % (controller_vtep_ip, controller_vtep_mac, vxlan_name))
        tunnel_utils.remove_ip_neigh(dev=vxlan_name,
                                     dst=controller_vtep_ip)
        # Remove the FDB entry that associate the VTEP MAC address
        # to the controller IP address
        logging.debug('Attempting to add the entry to the FDB\n'
                      'dst=%s, lladdr=%s, vxlan_name=%s'
                      % (self.controller_ip, controller_vtep_mac, vxlan_name))
        remove_fdb_entry(dev=vxlan_name, lladdr=controller_vtep_mac)
        # Remove the IP address assigned to the interface
        device_vtep_ip = self.device_vtep_ip
        vtep_mask = self.vtep_mask
        if device_vtep_ip is not None:
            logging.debug('Attempting to remove the IP address %s/%s '
                          'from the VXLAN management interface %s'
                          % (device_vtep_ip, vtep_mask, vxlan_name))
            tunnel_utils.del_address(device=vxlan_name,
                                     address=device_vtep_ip,
                                     mask=vtep_mask)
        # Remove the VTEP IP addresses
        self.controller_mgmtip = None
        self.device_vtep_ip = None
        self.device_vtep_mask = None
        # Success
        logging.debug('destroy_tunnel_device_endpoint_end() completed')
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_device_endpoint(self, deviceid, tenantid):
        logging.info('Destroying the VXLAN tunnel'
                     '(destroy_tunnel_device_endpoint)')
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Name of the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Delete the VXLAN interface
        logging.debug('Attempting to remove the VXLAN '
                      'interface %s' % vxlan_name)
        tunnel_utils.delete_interface(device=vxlan_name)
        # Remove the VTEP IP addresses
        self.controller_mgmtip = None
        self.device_vtep_ip = None
        self.device_vtep_mask = None
        # Success
        logging.debug('destroy_tunnel_device_endpoint() completed')
        logging.debug('The VXLAN interface has been removed')
        return status_codes_pb2.STATUS_SUCCESS

    def destroy_tunnel_controller_endpoint(self, deviceid, tenantid):
        logging.info('Destroying the VXLAN tunnel for the device %s'
                     % deviceid)
        # Extract the device ID
        #deviceid = deviceid
        # Extract the tenant ID
        #tenantid = tenantid
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Name of the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Remove the IP neighbor entry that associate the VTEP IP address
        # of the device to the device VTEP MAC address
        device_vtep_ip = srv6_sdn_controller_state.get_device_mgmtip(
            tenantid, deviceid).split('/')[0]
        logging.debug('Attempting to remove the neigh from the neigh table\n'
                      'dst=%s, vxlan_name=%s'
                      % (device_vtep_ip, vxlan_name))
        try:
            tunnel_utils.remove_ip_neigh(dev=vxlan_name,
                                         dst=device_vtep_ip)
        except pyroute2.netlink.exceptions.NetlinkError as e:
            if e.code == NO_SUCH_FILE_OR_DIRECTORY:
                logging.warning('Skipping remove_ip_neigh: %s' % e)
            else:
                logging.error('Error in remove_ip_neigh: %s' % e)
                return status_codes_pb2.STATUS_INTERNAL_ERROR
        # Remove the FDB entry that associate the device VTEP MAC address
        # to the device IP address
        device_vtep_mac = srv6_sdn_controller_state.get_device_vtep_mac(
            deviceid, tenantid)
        logging.debug('Attempting to remove the entry from the FDB\n'
                      'lladdr=%s, vxlan_name=%s'
                      % (device_vtep_mac, vxlan_name))
        remove_fdb_entry(dev=vxlan_name, lladdr=device_vtep_mac)
        # Release the private IP address associated to the device
        srv6_sdn_controller_state.release_ipv4_address(
            deviceid, tenantid)        # TODO error check
        srv6_sdn_controller_state.release_ipv6_address(deviceid, tenantid)
        # Success
        logging.debug('The VXLAN interface has been removed')
        return status_codes_pb2.STATUS_SUCCESS

    def update_tunnel_device_endpoint(self, deviceid, tenantid,
                                      controller_vtep_ip,
                                      device_vtep_ip, vtep_mask,
                                      controller_vtep_mac):
        res = self.destroy_tunnel_device_endpoint(deviceid)
        if res == status_codes_pb2.STATUS_SUCCESS:
            res = self.create_tunnel_device_endpoint(deviceid, tenantid,
                                                     controller_vtep_ip,
                                                     device_vtep_ip, vtep_mask,
                                                     controller_vtep_mac)
        return res

    def update_tunnel_device_endpoint_end(self, deviceid, tenantid,
                                          controller_vtep_ip,
                                          device_vtep_ip, vtep_mask,
                                          controller_vtep_mac):
        return self.create_tunnel_device_endpoint_end(deviceid, tenantid,
                                                      controller_vtep_ip,
                                                      device_vtep_ip,
                                                      vtep_mask,
                                                      controller_vtep_mac)

    def update_tunnel_controller_endpoint(self, deviceid, tenantid,
                                          device_external_ip,
                                          device_external_port,
                                          device_vtep_mask, vxlan_port,
                                          device_vtep_mac):
        res = self.destroy_tunnel_controller_endpoint(
            deviceid, tenantid)
        if res == status_codes_pb2.STATUS_SUCCESS:
            res = self.create_tunnel_controller_endpoint(
                deviceid, tenantid, device_external_ip,
                device_external_port,
                device_vtep_mask, vxlan_port,
                device_vtep_mac
            )
        return res

    # Init tunnel controller endpoing
    def init_tunnel_controller_endpoint(self):
        # Tenant ID used to store management information
        tenantid = '0'
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Generate private addresses for the controller VTEP
        # ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv6(
        #    '0', tenantid).split('/')
        #controller_vtep_ipv6 = ip_mask[0]
        #vtep_mask_ipv6 = int(ip_mask[1])
        # ip_mask = srv6_sdn_controller_state.get_new_mgmt_ipv4(
        #    '0', tenantid).split('/')
        #controller_vtep_ipv4 = ip_mask[0]
        #vtep_mask_ipv4 = int(ip_mask[1])
        controller_vtep_ipv4 = '169.254.0.1'
        vtep_mask_ipv4 = 16
        controller_vtep_ipv6 = 'fcfa::1'
        vtep_mask_ipv6 = 16
        # Create the VXLAN interface
        logging.debug('First VXLAN tunnel, attempting to create '
                      'the VXLAN interface %s'
                      % vxlan_name)
        create_vxlan(device=vxlan_name, vni=vni,
                     # remote=device_external_ip,
                     local=self.controller_ip,
                     dstport=VXLAN_DSTPORT,
                     srcport_min=VXLAN_DSTPORT,
                     srcport_max=VXLAN_DSTPORT+1, udpcsum=ENABLE_UDP_CSUM,
                     udp6zerocsumtx=ENABLE_UDP_CSUM,
                     udp6zerocsumrx=not ENABLE_UDP_CSUM,
                     learning=False)
        # Bring the interface UP
        logging.debug('Bringing the interface %s up' % vxlan_name)
        tunnel_utils.enable_interface(device=vxlan_name)
        # Add a private address to the interface
        logging.debug('Attempting to assign the IP address %s/%s '
                      'to the VXLAN management interface %s'
                      % (controller_vtep_ipv6, vtep_mask_ipv6, vxlan_name))
        tunnel_utils.add_address(device=vxlan_name,
                                 address=controller_vtep_ipv6,
                                 mask=vtep_mask_ipv6)
        # Add a private address to the interface
        logging.debug('Attempting to assign the IP address %s/%s '
                      'to the VXLAN management interface %s'
                      % (controller_vtep_ipv4, vtep_mask_ipv4, vxlan_name))
        tunnel_utils.add_address(device=vxlan_name,
                                 address=controller_vtep_ipv4,
                                 mask=vtep_mask_ipv4)
        # Success
        return status_codes_pb2.STATUS_SUCCESS

    # Destroy tunnel controller endpoint
    def destr_tunnel_controller_endpoint(self):
        # Tenant ID used to store management information
        tenantid = 0
        # VNI used for VXLAN management interface
        vni = MGMT_VNI
        # Create the VXLAN interface
        vxlan_name = '%s-%s' % (self.name, vni)
        # Remove the address from the VTEP interface
        ip_mask = srv6_sdn_controller_state.get_device_mgmtipv4(
            tenantid, '0').split('/')
        controller_vtep_ipv4 = ip_mask[0]
        vtep_mask_ipv4 = ip_mask[1]
        logging.debug('Attempting to remove the IP address %s/%s '
                      'from the VXLAN management interface %s'
                      % (controller_vtep_ipv4, vtep_mask_ipv4, vxlan_name))
        tunnel_utils.del_address(device=vxlan_name,
                                 address=controller_vtep_ipv4,
                                 mask=vtep_mask_ipv4)
        # Remove the address from the VTEP interface
        ip_mask = srv6_sdn_controller_state.get_device_mgmtipv6(
            tenantid, '0').split('/')
        controller_vtep_ipv6 = ip_mask[0]
        vtep_mask_ipv6 = ip_mask[1]
        logging.debug('Attempting to remove the IP address %s/%s '
                      'from the VXLAN management interface %s'
                      % (controller_vtep_ipv6, vtep_mask_ipv6, vxlan_name))
        tunnel_utils.del_address(device=vxlan_name,
                                 address=controller_vtep_ipv6,
                                 mask=vtep_mask_ipv6)
        # Remove the VXLAN interface
        logging.debug('Last VXLAN tunnel, attempting to remove '
                      'the VXLAN interface %s'
                      % vxlan_name)
        tunnel_utils.remove_interface(device=vxlan_name)
        # Success
        return status_codes_pb2.STATUS_SUCCESS
