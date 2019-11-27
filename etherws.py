#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#                          Ethernet over WebSocket
#
# depends on:
#   - python-2.7.5
#   - python-pytun-2.1
#   - websocket-client-0.14.0
#   - tornado-2.4
#
# ===========================================================================
# Copyright (c) 2012-2015, Atzm WATANABE <atzm@atzm.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===========================================================================
#
# $Id: etherws.py 281 2015-06-25 09:59:54Z atzm $

import os
import sys
import ssl
import time
import json
import fcntl
import base64
import socket
import struct
import urllib.request, urllib.error, urllib.parse
import hashlib
import getpass
import operator
import argparse

import logging
import logging.config

import tornado
import websocket

from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI


class EthernetFrame(object):
    def __init__(self, data):
        self.data = data

    @property
    def dst_multicast(self):
        return self.data[0] & 1

    @property
    def src_multicast(self):
        return self.data[6] & 1

    @property
    def dst_mac(self):
        return self.data[:6]

    @property
    def src_mac(self):
        return self.data[6:12]

    @property
    def tagged(self):
        return self.data[12] == 0x81 and self.data[13] == 0

    @property
    def vid(self):
        if self.tagged:
            return ((self.data[14] << 8) | self.data[15]) & 0x0fff
        return 0

    @staticmethod
    def format_mac(mac, sep=':'):
        return sep.join(b.encode().hex() for b in mac)


class FDB(object):
    class Entry(object):
        def __init__(self, port, ageout):
            self.port = port
            self._time = time.time()
            self._ageout = ageout

        @property
        def age(self):
            return time.time() - self._time

        @property
        def agedout(self):
            return self.age > self._ageout

    def __init__(self, ageout, logger, debug):
        self._ageout = ageout
        self._logger = logger
        self._debug = debug
        self._table = {}

    def _set_entry(self, vid, mac, port):
        if vid not in self._table:
            self._table[vid] = {}
        self._table[vid][mac] = self.Entry(port, self._ageout)

    def _del_entry(self, vid, mac):
        if vid in self._table:
            if mac in self._table[vid]:
                del self._table[vid][mac]
            if not self._table[vid]:
                del self._table[vid]

    def _get_entry(self, vid, mac):
        try:
            entry = self._table[vid][mac]
        except KeyError:
            return None

        if not entry.agedout:
            return entry

        self._del_entry(vid, mac)

        if self._debug:
            self._logger.debug('fdb aged out: port:%d; vid:%d; mac:%s',
                               entry.port.number, vid, mac.hex())

    def each(self):
        for vid in sorted(self._table.keys()):
            for mac in sorted(self._table[vid].keys()):
                entry = self._get_entry(vid, mac)
                if entry:
                    yield (vid, mac, entry)

    def lookup(self, frame):
        mac = frame.dst_mac
        vid = frame.vid
        entry = self._get_entry(vid, mac)
        return getattr(entry, 'port', None)

    def learn(self, port, frame):
        mac = frame.src_mac
        vid = frame.vid
        self._set_entry(vid, mac, port)

        if self._debug:
            self._logger.debug('fdb learned: port:%d; vid:%d; mac:%s',
                               port.number, vid, mac.hex())

    def delete(self, port):
        for vid, mac, entry in self.each():
            if entry.port.number == port.number:
                self._del_entry(vid, mac)

                if self._debug:
                    self._logger.debug('fdb deleted: port:%d; vid:%d; mac:%s',
                                       port.number, vid, mac.hex())


class SwitchingHub(object):
    class Port(object):
        def __init__(self, number, interface):
            self.number = number
            self.interface = interface
            self.tx = 0
            self.rx = 0
            self.shut = False

    def __init__(self, fdb, logger, debug):
        self.fdb = fdb
        self._logger = logger
        self._debug = debug
        self._table = {}
        self._next = 1

    @property
    def portlist(self):
        return sorted(iter(self._table.values()),
                      key=operator.attrgetter('number'))

    def get_port(self, portnum):
        return self._table[portnum]

    def register_port(self, interface):
        try:
            self._set_privattr('portnum', interface, self._next)  # XXX
            self._table[self._next] = self.Port(self._next, interface)
            return self._next
        finally:
            self._next += 1

    def unregister_port(self, interface):
        portnum = self._get_privattr('portnum', interface)
        self._del_privattr('portnum', interface)
        self.fdb.delete(self._table[portnum])
        del self._table[portnum]

    def send(self, dst_interfaces, frame):
        portnums = (self._get_privattr('portnum', i) for i in dst_interfaces)
        ports = (self._table[n] for n in portnums)
        ports = (p for p in ports if not p.shut)
        ports = sorted(ports, key=operator.attrgetter('number'))

        for p in ports:
            p.interface.write_message(frame.data, True)
            p.tx += 1

        if self._debug and ports:
            self._logger.debug('sent: port:%s; vid:%d; %s -> %s',
                               ','.join(str(p.number) for p in ports),
                               frame.vid,
                               frame.src_mac.hex(),
                               frame.dst_mac.hex())

    def receive(self, src_interface, frame):
        port = self._table[self._get_privattr('portnum', src_interface)]

        if not port.shut:
            port.rx += 1
            self._forward(port, frame)

    def _forward(self, src_port, frame):
        try:
            if not frame.src_multicast:
                self.fdb.learn(src_port, frame)

            if not frame.dst_multicast:
                dst_port = self.fdb.lookup(frame)

                if dst_port:
                    self.send([dst_port.interface], frame)
                    return

            ports = set(self.portlist) - set([src_port])
            self.send((p.interface for p in ports), frame)

        except:  # ex. received invalid frame
            self._logger.exception(
                'caught error while forwarding frame: port:%d; frame:%s',
                src_port.number, frame.data.encode().hex())

    def _privattr(self, name):
        return '_%s_%s_%s' % (type(self).__name__, id(self), name)

    def _set_privattr(self, name, obj, value):
        return setattr(obj, self._privattr(name), value)

    def _get_privattr(self, name, obj, defaults=None):
        return getattr(obj, self._privattr(name), defaults)

    def _del_privattr(self, name, obj):
        return delattr(obj, self._privattr(name))


class NetworkInterface(object):
    SIOCGIFADDR = 0x8915  # from <linux/sockios.h>
    SIOCSIFADDR = 0x8916
    SIOCGIFNETMASK = 0x891b
    SIOCSIFNETMASK = 0x891c
    SIOCGIFMTU = 0x8921
    SIOCSIFMTU = 0x8922

    def __init__(self, ifname):
        self._ifname = struct.pack('16s', str(ifname)[:15])

    def _ioctl(self, req, data):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return fcntl.ioctl(sock.fileno(), req, data)
        finally:
            sock.close()

    @property
    def address(self):
        try:
            data = struct.pack('16s18x', self._ifname)
            ret = self._ioctl(self.SIOCGIFADDR, data)
            return socket.inet_ntoa(ret[20:24])
        except IOError:
            return ''

    @property
    def netmask(self):
        try:
            data = struct.pack('16s18x', self._ifname)
            ret = self._ioctl(self.SIOCGIFNETMASK, data)
            return socket.inet_ntoa(ret[20:24])
        except IOError:
            return ''

    @property
    def mtu(self):
        try:
            data = struct.pack('16s18x', self._ifname)
            ret = self._ioctl(self.SIOCGIFMTU, data)
            return struct.unpack('i', ret[16:20])[0]
        except IOError:
            return 0

    @address.setter
    def address(self, addr):
        data = struct.pack('16si4s10x', self._ifname, socket.AF_INET,
                           socket.inet_aton(addr))
        self._ioctl(self.SIOCSIFADDR, data)

    @netmask.setter
    def netmask(self, addr):
        data = struct.pack('16si4s10x', self._ifname, socket.AF_INET,
                           socket.inet_aton(addr))
        self._ioctl(self.SIOCSIFNETMASK, data)

    @mtu.setter
    def mtu(self, mtu):
        data = struct.pack('16si12x', self._ifname, mtu)
        self._ioctl(self.SIOCSIFMTU, data)


class Htpasswd(object):
    def __init__(self, path):
        self._path = path
        self._stat = None
        self._data = {}

    def auth(self, name, passwd):
        passwd = base64.b64encode(hashlib.sha1(passwd).digest())
        return self._data.get(name) == passwd

    def load(self):
        old_stat = self._stat

        with open(self._path) as fp:
            fileno = fp.fileno()
            fcntl.flock(fileno, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self._stat = os.fstat(fileno)

            unchanged = old_stat and \
                old_stat.st_ino == self._stat.st_ino and \
                old_stat.st_dev == self._stat.st_dev and \
                old_stat.st_mtime == self._stat.st_mtime

            if not unchanged:
                self._data = self._parse(fp)

        return self

    def _parse(self, fp):
        data = {}
        for line in fp:
            line = line.strip()
            if 0 <= line.find(':'):
                name, passwd = line.split(':', 1)
                if passwd.startswith('{SHA}'):
                    data[name] = passwd[5:]
        return data


class BasicAuthMixIn(object):
    def _execute(self, transforms, *args, **kwargs):
        def do_execute():
            sp = super(BasicAuthMixIn, self)
            return sp._execute(transforms, *args, **kwargs)

        def auth_required():
            stream = getattr(self, 'stream', self.request.connection.stream)
            stream.write(tornado.escape.utf8(
                'HTTP/1.1 401 Authorization Required\r\n'
                'WWW-Authenticate: Basic realm=etherws\r\n\r\n'
            ))
            stream.close()

        try:
            if not self._htpasswd:
                return do_execute()

            creds = self.request.headers.get('Authorization')

            if not creds or not creds.startswith('Basic '):
                return auth_required()

            name, passwd = base64.b64decode(creds[6:]).split(':', 1)

            if self._htpasswd.load().auth(name, passwd):
                return do_execute()
        except:
            self._logger.exception('caught error while doing authorization')

        return auth_required()


class ServerHandler(BasicAuthMixIn, WebSocketHandler):
    IFTYPE = 'server'
    IFOP_ALLOWED = False

    def __init__(self, app, req, switch, htpasswd, logger, debug):
        super(ServerHandler, self).__init__(app, req)
        self._switch = switch
        self._htpasswd = htpasswd
        self._logger = logger
        self._debug = debug

    @property
    def target(self):
        conn = self.request.connection
        if hasattr(conn, 'address'):
            return ':'.join(str(e) for e in conn.address[:2])
        if hasattr(conn, 'context'):
            return ':'.join(str(e) for e in conn.context.address[:2])
        return str(conn)

    def open(self):
        try:
            #return self._switch.register_port(self)
            self._switch.register_port(self)
        finally:
            self._logger.info('connected: %s', self.request.remote_ip)

    def on_message(self, message):
        self._switch.receive(self, EthernetFrame(message))

    def on_close(self):
        self._switch.unregister_port(self)
        self._logger.info('disconnected: %s', self.request.remote_ip)


class BaseClientHandler(object):
    IFTYPE = 'baseclient'
    IFOP_ALLOWED = False

    def __init__(self, ioloop, switch, target, logger, debug, *args, **kwargs):
        self._ioloop = ioloop
        self._switch = switch
        self._target = target
        self._logger = logger
        self._debug = debug
        self._args = args
        self._kwargs = kwargs
        self._device = None

    @property
    def address(self):
        raise NotImplementedError('unsupported')

    @property
    def netmask(self):
        raise NotImplementedError('unsupported')

    @property
    def mtu(self):
        raise NotImplementedError('unsupported')

    @address.setter
    def address(self, address):
        raise NotImplementedError('unsupported')

    @netmask.setter
    def netmask(self, netmask):
        raise NotImplementedError('unsupported')

    @mtu.setter
    def mtu(self, mtu):
        raise NotImplementedError('unsupported')

    def open(self):
        raise NotImplementedError('unsupported')

    def write_message(self, message, binary=False):
        raise NotImplementedError('unsupported')

    def read(self):
        raise NotImplementedError('unsupported')

    @property
    def target(self):
        return self._target

    @property
    def logger(self):
        return self._logger

    @property
    def device(self):
        return self._device

    @property
    def closed(self):
        return not self.device

    def close(self):
        if self.closed:
            raise ValueError('I/O operation on closed %s' % self.IFTYPE)
        self.leave_switch()
        self.unregister_device()
        self.logger.info('disconnected: %s', self.target)

    def register_device(self, device):
        self._device = device

    def unregister_device(self):
        self._device.close()
        self._device = None

    def fileno(self):
        if self.closed:
            raise ValueError('I/O operation on closed %s' % self.IFTYPE)
        return self.device.fileno()

    def __call__(self, fd, events):
        try:
            data = self.read()
            if data is not None:
                self._switch.receive(self, EthernetFrame(data))
                return
        except:
            self.logger.exception('caught error while receiving frame')
        self.close()

    def join_switch(self):
        self._ioloop.add_handler(self.fileno(), self, self._ioloop.READ)
        return self._switch.register_port(self)

    def leave_switch(self):
        self._switch.unregister_port(self)
        self._ioloop.remove_handler(self.fileno())


class NetdevHandler(BaseClientHandler):
    IFTYPE = 'netdev'
    IFOP_ALLOWED = True
    ETH_P_ALL = 0x0003  # from <linux/if_ether.h>

    @property
    def address(self):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        return NetworkInterface(self.target).address

    @property
    def netmask(self):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        return NetworkInterface(self.target).netmask

    @property
    def mtu(self):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        return NetworkInterface(self.target).mtu

    @address.setter
    def address(self, address):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        NetworkInterface(self.target).address = address

    @netmask.setter
    def netmask(self, netmask):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        NetworkInterface(self.target).netmask = netmask

    @mtu.setter
    def mtu(self, mtu):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        NetworkInterface(self.target).mtu = mtu

    def open(self):
        if not self.closed:
            raise ValueError('Already opened')
        self.register_device(socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL)))
        self.device.bind((self.target, self.ETH_P_ALL))
        self.logger.info('connected: %s', self.target)
        return self.join_switch()

    def write_message(self, message, binary=False):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        self.device.sendall(message)

    def read(self):
        if self.closed:
            raise ValueError('I/O operation on closed netdev')
        buf = []
        while True:
            buf.append(self.device.recv(65535))
            if len(buf[-1]) < 65535:
                break
        return ''.join(buf)


class TapHandler(BaseClientHandler):
    IFTYPE = 'tap'
    IFOP_ALLOWED = True

    @property
    def address(self):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        try:
            return self.device.addr
        except:
            return ''

    @property
    def netmask(self):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        try:
            return self.device.netmask
        except:
            return ''

    @property
    def mtu(self):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        return self.device.mtu

    @address.setter
    def address(self, address):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        self.device.addr = address

    @netmask.setter
    def netmask(self, netmask):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        self.device.netmask = netmask

    @mtu.setter
    def mtu(self, mtu):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        self.device.mtu = mtu

    @property
    def target(self):
        if self.closed:
            return self._target
        return self.device.name

    def open(self):
        if not self.closed:
            raise ValueError('Already opened')
        self.register_device(TunTapDevice(self.target, IFF_TAP | IFF_NO_PI))
        self.device.up()
        self.logger.info('connected: %s', self.target)
        return self.join_switch()

    def write_message(self, message, binary=False):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        self.device.write(message)

    def read(self):
        if self.closed:
            raise ValueError('I/O operation on closed tap')
        buf = bytes()
        while True:
            b = self.device.read(65535)
            buf += b
            if len(b) < 65535:
                break
        return buf


class ClientHandler(BaseClientHandler):
    IFTYPE = 'client'
    IFOP_ALLOWED = False

    def __init__(self, *args, **kwargs):
        super(ClientHandler, self).__init__(*args, **kwargs)
        self._sslopt = self._kwargs.get('sslopt', {})
        self._options = dict(self.authopts, **self.proxyopts)

    def open(self):
        if not self.closed:
            raise websocket.WebSocketException('Already opened')

        # XXX: may be blocked
        self.register_device(websocket.WebSocket(sslopt=self._sslopt))
        self.device.connect(self.target, **self._options)
        self.logger.info('connected: %s', self.target)
        return self.join_switch()

    def write_message(self, message, binary=False):
        if self.closed:
            raise websocket.WebSocketException('Closed socket')
        if binary:
            flag = websocket.ABNF.OPCODE_BINARY
        else:
            flag = websocket.ABNF.OPCODE_TEXT
        self.device.send(message, flag)

    def read(self):
        if self.closed:
            raise websocket.WebSocketException('Closed socket')
        return self.device.recv()

    @property
    def authopts(self):
        cred = self._kwargs.get('cred')

        if not isinstance(cred, dict):
            return {}
        if 'user' not in cred:
            return {}
        if 'passwd' not in cred:
            return {}

        token = base64.b64encode(('%s:%s' % (cred['user'], cred['passwd'])).encode())
        return {'header': ['Authorization: Basic %s' % token]}

    @property
    def proxyopts(self):
        scheme, remain = urllib.parse.splittype(self.target)

        proxy = urllib.request.getproxies().get(scheme.replace('ws', 'http'))
        if not proxy:
            return {}

        host = urllib.parse.splitport(urllib.parse.splithost(remain)[0])[0]
        if urllib.request.proxy_bypass(host):
            return {}

        hostport = urllib.parse.splithost(urllib.parse.splittype(proxy)[1])[0]
        host, port = urllib.parse.splitport(hostport)
        port = int(port) if port else 0
        return {'http_proxy_host': host, 'http_proxy_port': port}


class ControlServerHandler(BasicAuthMixIn, RequestHandler):
    NAMESPACE = 'etherws.control'
    IFTYPES = {
        NetdevHandler.IFTYPE: NetdevHandler,
        TapHandler.IFTYPE:    TapHandler,
        ClientHandler.IFTYPE: ClientHandler,
    }

    def __init__(self, app, req, ioloop, switch, htpasswd, logger, debug):
        super(ControlServerHandler, self).__init__(app, req)
        self._ioloop = ioloop
        self._switch = switch
        self._htpasswd = htpasswd
        self._logger = logger
        self._debug = debug

    def post(self):
        try:
            request = json.loads(self.request.body)
        except Exception as e:
            return self._jsonrpc_response(error={
                'code':    0 - 32700,
                'message': 'Parse error',
                'data':    '%s: %s' % (type(e).__name__, str(e)),
            })

        try:
            id_ = request.get('id')
            params = request.get('params')
            version = request['jsonrpc']
            method = request['method']
            if version != '2.0':
                raise ValueError('Invalid JSON-RPC version: %s' % version)
        except Exception as e:
            return self._jsonrpc_response(id_=id_, error={
                'code':    0 - 32600,
                'message': 'Invalid Request',
                'data':    '%s: %s' % (type(e).__name__, str(e)),
            })

        try:
            if not method.startswith(self.NAMESPACE + '.'):
                raise ValueError('Invalid method namespace: %s' % method)
            handler = 'handle_' + method[len(self.NAMESPACE) + 1:]
            handler = getattr(self, handler)
        except Exception as e:
            return self._jsonrpc_response(id_=id_, error={
                'code':    0 - 32601,
                'message': 'Method not found',
                'data':    '%s: %s' % (type(e).__name__, str(e)),
            })

        try:
            return self._jsonrpc_response(id_=id_, result=handler(params))
        except Exception as e:
            self._logger.exception('caught error while processing request')
            return self._jsonrpc_response(id_=id_, error={
                'code':    0 - 32602,
                'message': 'Invalid params',
                'data':     '%s: %s' % (type(e).__name__, str(e)),
            })

    def handle_listFdb(self, params):
        list_ = []
        for vid, mac, entry in self._switch.fdb.each():
            list_.append({
                'vid':  vid,
                'mac':  EthernetFrame.format_mac(mac),
                'port': entry.port.number,
                'age':  int(entry.age),
            })
        return {'entries': list_}

    def handle_listPort(self, params):
        return {'entries': [self._portstat(p) for p in self._switch.portlist]}

    def handle_addPort(self, params):
        type_ = params['type']
        target = params['target']
        opt = getattr(self, '_optparse_' + type_)(params.get('options', {}))
        cls = self.IFTYPES[type_]
        interface = cls(self._ioloop, self._switch, target,
                        self._logger, self._debug, **opt)
        portnum = interface.open()
        return {'entries': [self._portstat(self._switch.get_port(portnum))]}

    def handle_setPort(self, params):
        port = self._switch.get_port(int(params['port']))
        shut = params.get('shut')
        if shut is not None:
            port.shut = bool(shut)
        return {'entries': [self._portstat(port)]}

    def handle_delPort(self, params):
        port = self._switch.get_port(int(params['port']))
        port.interface.close()
        return {'entries': [self._portstat(port)]}

    def handle_setInterface(self, params):
        portnum = int(params['port'])
        port = self._switch.get_port(portnum)
        address = params.get('address')
        netmask = params.get('netmask')
        mtu = params.get('mtu')
        if not port.interface.IFOP_ALLOWED:
            raise ValueError('Port %d has unsupported interface: %s' %
                             (portnum, port.interface.IFTYPE))
        if address is not None:
            port.interface.address = address
        if netmask is not None:
            port.interface.netmask = netmask
        if mtu is not None:
            port.interface.mtu = mtu
        return {'entries': [self._ifstat(port)]}

    def handle_listInterface(self, params):
        return {'entries': [self._ifstat(p) for p in self._switch.portlist
                            if p.interface.IFOP_ALLOWED]}

    def _optparse_netdev(self, opt):
        return {}

    def _optparse_tap(self, opt):
        return {}

    def _optparse_client(self, opt):
        if opt.get('insecure'):
            sslopt = {'cert_reqs': ssl.CERT_NONE}
        else:
            sslopt = {'cert_reqs': ssl.CERT_REQUIRED,
                      'ca_certs':  opt.get('cacerts')}
        cred = {'user': opt.get('user'), 'passwd': opt.get('passwd')}
        return {'sslopt': sslopt, 'cred': cred}

    def _jsonrpc_response(self, id_=None, result=None, error=None):
        res = {'jsonrpc': '2.0', 'id': id_}
        if result:
            res['result'] = result
        if error:
            res['error'] = error
        self.finish(res)

    @staticmethod
    def _portstat(port):
        return {
            'port':   port.number,
            'type':   port.interface.IFTYPE,
            'target': port.interface.target,
            'tx':     port.tx,
            'rx':     port.rx,
            'shut':   port.shut,
        }

    @staticmethod
    def _ifstat(port):
        return {
            'port':    port.number,
            'type':    port.interface.IFTYPE,
            'target':  port.interface.target,
            'address': port.interface.address,
            'netmask': port.interface.netmask,
            'mtu':     port.interface.mtu,
        }


def _print_error(error):
    print(('  %s (%s)' % (error['message'], error['code'])))
    print(('    %s' % error['data']))


def _start_sw(args):
    def daemonize(nochdir=False, noclose=False):
        if os.fork() > 0:
            sys.exit(0)

        os.setsid()

        if os.fork() > 0:
            sys.exit(0)

        if not nochdir:
            os.chdir('/')

        if not noclose:
            os.umask(0)
            sys.stdin.close()
            sys.stdout.close()
            sys.stderr.close()
            os.close(0)
            os.close(1)
            os.close(2)
            sys.stdin = open(os.devnull)
            sys.stdout = open(os.devnull, 'a')
            sys.stderr = open(os.devnull, 'a')

    def checkabspath(ns, path):
        val = getattr(ns, path, '')
        if not val.startswith('/'):
            raise ValueError('Invalid %: %s' % (path, val))

    def getsslopt(ns, key, cert):
        kval = getattr(ns, key, None)
        cval = getattr(ns, cert, None)
        if kval and cval:
            return {'keyfile': kval, 'certfile': cval}
        elif kval or cval:
            raise ValueError('Both %s and %s are required' % (key, cert))
        return None

    def setrealpath(ns, *keys):
        for k in keys:
            v = getattr(ns, k, None)
            if v is not None:
                v = os.path.realpath(v)
                open(v).close()  # check readable
                setattr(ns, k, v)

    def setport(ns, port, isssl):
        val = getattr(ns, port, None)
        if val is None:
            if isssl:
                return setattr(ns, port, 443)
            return setattr(ns, port, 80)
        if not (0 <= val <= 65535):
            raise ValueError('Invalid %s: %s' % (port, val))

    def sethtpasswd(ns, htpasswd):
        val = getattr(ns, htpasswd, None)
        if val:
            return setattr(ns, htpasswd, Htpasswd(val))

    # if args.debug:
    #     websocket.enableTrace(True)

    if args.ageout <= 0:
        raise ValueError('Invalid ageout: %s' % args.ageout)

    setrealpath(args, 'logconf')
    setrealpath(args, 'htpasswd', 'sslkey', 'sslcert')
    setrealpath(args, 'ctlhtpasswd', 'ctlsslkey', 'ctlsslcert')

    checkabspath(args, 'path')
    checkabspath(args, 'ctlpath')

    sslopt = getsslopt(args, 'sslkey', 'sslcert')
    ctlsslopt = getsslopt(args, 'ctlsslkey', 'ctlsslcert')

    setport(args, 'port', sslopt)
    setport(args, 'ctlport', ctlsslopt)

    sethtpasswd(args, 'htpasswd')
    sethtpasswd(args, 'ctlhtpasswd')

    if args.logconf:
        logging.config.fileConfig(args.logconf)
        logger = logging.getLogger('etherws')
    else:
        logger = logging.getLogger('etherws')
        logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    ioloop = IOLoop.instance()
    fdb = FDB(args.ageout, logger, args.debug)
    switch = SwitchingHub(fdb, logger, args.debug)

    if args.port == args.ctlport and args.host == args.ctlhost:
        if args.path == args.ctlpath:
            raise ValueError('Same path/ctlpath on same host')
        if args.sslkey != args.ctlsslkey:
            raise ValueError('Different sslkey/ctlsslkey on same host')
        if args.sslcert != args.ctlsslcert:
            raise ValueError('Different sslcert/ctlsslcert on same host')

        app = Application([
            (args.path, ServerHandler, {
                'switch':   switch,
                'htpasswd': args.htpasswd,
                'logger':   logger,
                'debug':    args.debug,
            }),
            (args.ctlpath, ControlServerHandler, {
                'ioloop':   ioloop,
                'switch':   switch,
                'htpasswd': args.ctlhtpasswd,
                'logger':   logger,
                'debug':    args.debug,
            }),
        ])
        server = HTTPServer(app, ssl_options=sslopt)
        server.listen(args.port, address=args.host)

    else:
        app = Application([(args.path, ServerHandler, {
            'switch':   switch,
            'htpasswd': args.htpasswd,
            'logger':   logger,
            'debug':    args.debug,
        })])
        server = HTTPServer(app, ssl_options=sslopt)
        server.listen(args.port, address=args.host)

        ctl = Application([(args.ctlpath, ControlServerHandler, {
            'ioloop':   ioloop,
            'switch':   switch,
            'htpasswd': args.ctlhtpasswd,
            'logger':   logger,
            'debug':    args.debug,
        })])
        ctlserver = HTTPServer(ctl, ssl_options=ctlsslopt)
        ctlserver.listen(args.ctlport, address=args.ctlhost)

    if not args.foreground:
        daemonize()

    ioloop.start()


def _start_ctl(args):
    def have_ssl_cert_verification():
        return 'context' in urllib.request.urlopen.__code__.co_varnames

    def request(args, method, params=None, id_=0):
        req = urllib.request.Request(args.ctlurl)
        req.add_header('Content-type', 'application/json')
        if args.ctluser:
            if not args.ctlpasswd:
                args.ctlpasswd = getpass.getpass('Control Password: ')
            token = base64.b64encode('%s:%s' % (args.ctluser, args.ctlpasswd))
            req.add_header('Authorization', 'Basic %s' % token)
        method = '.'.join([ControlServerHandler.NAMESPACE, method])
        data = {'jsonrpc': '2.0', 'method': method, 'id': id_}
        if params is not None:
            data['params'] = params
        if have_ssl_cert_verification():
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH,
                                             cafile=args.ctlsslcert)
            if args.ctlinsecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            fp = urllib.request.urlopen(req, json.dumps(data).encode(), context=ctx)
        elif args.ctlsslcert:
            raise EnvironmentError('do not support certificate verification')
        else:
            fp = urllib.request.urlopen(req, json.dumps(data).encode())
        return json.loads(fp.read())

    def print_table(rows):
        cols = list(zip(*rows))
        maxlen = [0] * len(cols)
        for i in range(len(cols)):
            maxlen[i] = max(len(str(c)) for c in cols[i])
        fmt = '  '.join(['%%-%ds' % maxlen[i] for i in range(len(cols))])
        fmt = '  ' + fmt
        for row in rows:
            print((fmt % tuple(row)))

    def print_portlist(result):
        rows = [['Port', 'Type', 'State', 'RX', 'TX', 'Target']]
        for r in result:
            rows.append([r['port'], r['type'], 'shut' if r['shut'] else 'up',
                         r['rx'], r['tx'], r['target']])
        print_table(rows)

    def print_iflist(result):
        rows = [['Port', 'Type', 'Address', 'Netmask', 'MTU', 'Target']]
        for r in result:
            rows.append([r['port'], r['type'], r['address'],
                         r['netmask'], r['mtu'], r['target']])
        print_table(rows)

    def handle_ctl_addport(args):
        opts = {
            'user':     getattr(args, 'user', None),
            'passwd':   getattr(args, 'passwd', None),
            'cacerts':  getattr(args, 'cacerts', None),
            'insecure': getattr(args, 'insecure', None),
        }
        if args.iftype == ClientHandler.IFTYPE:
            if not args.target.startswith('ws://') and \
               not args.target.startswith('wss://'):
                raise ValueError('Invalid target URL scheme: %s' % args.target)
            if not opts['user'] and opts['passwd']:
                raise ValueError('Authentication required but username empty')
            if opts['user'] and not opts['passwd']:
                opts['passwd'] = getpass.getpass('Client Password: ')
        result = request(args, 'addPort', {
            'type':    args.iftype,
            'target':  args.target,
            'options': opts,
        })
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_portlist(result['result']['entries'])

    def handle_ctl_setport(args):
        if args.port <= 0:
            raise ValueError('Invalid port: %d' % args.port)
        req = {'port': args.port}
        shut = getattr(args, 'shut', None)
        if shut is not None:
            req['shut'] = bool(shut)
        result = request(args, 'setPort', req)
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_portlist(result['result']['entries'])

    def handle_ctl_delport(args):
        if args.port <= 0:
            raise ValueError('Invalid port: %d' % args.port)
        result = request(args, 'delPort', {'port': args.port})
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_portlist(result['result']['entries'])

    def handle_ctl_listport(args):
        result = request(args, 'listPort')
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_portlist(result['result']['entries'])

    def handle_ctl_setif(args):
        if args.port <= 0:
            raise ValueError('Invalid port: %d' % args.port)
        req = {'port': args.port}
        address = getattr(args, 'address', None)
        netmask = getattr(args, 'netmask', None)
        mtu = getattr(args, 'mtu', None)
        if address is not None:
            if address:
                socket.inet_aton(address)  # validate
            req['address'] = address
        if netmask is not None:
            if netmask:
                socket.inet_aton(netmask)  # validate
            req['netmask'] = netmask
        if mtu is not None:
            if mtu < 576:
                raise ValueError('Invalid MTU: %d' % mtu)
            req['mtu'] = mtu
        result = request(args, 'setInterface', req)
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_iflist(result['result']['entries'])

    def handle_ctl_listif(args):
        result = request(args, 'listInterface')
        if 'error' in result:
            _print_error(result['error'])
        else:
            print_iflist(result['result']['entries'])

    def handle_ctl_listfdb(args):
        result = request(args, 'listFdb')
        if 'error' in result:
            return _print_error(result['error'])
        rows = [['Port', 'VLAN', 'MAC', 'Age']]
        for r in result['result']['entries']:
            rows.append([r['port'], r['vid'], r['mac'], r['age']])
        print_table(rows)

    locals()['handle_ctl_' + args.control_method](args)


def _main():
    parser = argparse.ArgumentParser()
    subcommand = parser.add_subparsers(dest='subcommand')

    # - sw
    parser_sw = subcommand.add_parser('sw',
                                      help='start virtual switch')

    parser_sw.add_argument('--debug', action='store_true', default=False,
                           help='run as debug mode')
    parser_sw.add_argument('--logconf',
                           help='path to logging config')
    parser_sw.add_argument('--foreground', action='store_true', default=False,
                           help='run as foreground mode')
    parser_sw.add_argument('--ageout', type=int, default=300,
                           help='FDB ageout time (sec)')

    parser_sw.add_argument('--path', default='/',
                           help='http(s) path to serve WebSocket')
    parser_sw.add_argument('--host', default='',
                           help='listen address to serve WebSocket')
    parser_sw.add_argument('--port', type=int,
                           help='listen port to serve WebSocket')
    parser_sw.add_argument('--htpasswd',
                           help='path to htpasswd file to auth WebSocket')
    parser_sw.add_argument('--sslkey',
                           help='path to SSL private key for WebSocket')
    parser_sw.add_argument('--sslcert',
                           help='path to SSL certificate for WebSocket')

    parser_sw.add_argument('--ctlpath', default='/ctl',
                           help='http(s) path to serve control API')
    parser_sw.add_argument('--ctlhost', default='127.0.0.1',
                           help='listen address to serve control API')
    parser_sw.add_argument('--ctlport', type=int, default=7867,
                           help='listen port to serve control API')
    parser_sw.add_argument('--ctlhtpasswd',
                           help='path to htpasswd file to auth control API')
    parser_sw.add_argument('--ctlsslkey',
                           help='path to SSL private key for control API')
    parser_sw.add_argument('--ctlsslcert',
                           help='path to SSL certificate for control API')

    # - ctl
    parser_ctl = subcommand.add_parser('ctl',
                                       help='control virtual switch')
    parser_ctl.add_argument('--ctlurl', default='http://127.0.0.1:7867/ctl',
                            help='URL to control API')
    parser_ctl.add_argument('--ctluser',
                            help='username to auth control API')
    parser_ctl.add_argument('--ctlpasswd',
                            help='password to auth control API')
    parser_ctl.add_argument('--ctlsslcert',
                            help='path to SSL certificate for control API')
    parser_ctl.add_argument(
        '--ctlinsecure', action='store_true', default=False,
        help='do not verify control API certificate')

    control_method = parser_ctl.add_subparsers(dest='control_method')

    # -- ctl addport
    parser_ctl_addport = control_method.add_parser('addport',
                                                   help='create and add port')
    iftype = parser_ctl_addport.add_subparsers(dest='iftype')

    # --- ctl addport netdev
    parser_ctl_addport_netdev = iftype.add_parser(NetdevHandler.IFTYPE,
                                                  help='Network device')
    parser_ctl_addport_netdev.add_argument('target',
                                           help='device name to add interface')

    # --- ctl addport tap
    parser_ctl_addport_tap = iftype.add_parser(TapHandler.IFTYPE,
                                               help='TAP device')
    parser_ctl_addport_tap.add_argument('target',
                                        help='device name to create interface')

    # --- ctl addport client
    parser_ctl_addport_client = iftype.add_parser(ClientHandler.IFTYPE,
                                                  help='WebSocket client')
    parser_ctl_addport_client.add_argument('target',
                                           help='URL to connect WebSocket')
    parser_ctl_addport_client.add_argument('--user',
                                           help='username to auth WebSocket')
    parser_ctl_addport_client.add_argument('--passwd',
                                           help='password to auth WebSocket')
    parser_ctl_addport_client.add_argument('--cacerts',
                                           help='path to CA certificate')
    parser_ctl_addport_client.add_argument(
        '--insecure', action='store_true', default=False,
        help='do not verify server certificate')

    # -- ctl setport
    parser_ctl_setport = control_method.add_parser('setport',
                                                   help='set port config')
    parser_ctl_setport.add_argument('port', type=int,
                                    help='port number to set config')
    parser_ctl_setport.add_argument('--shut', type=int, choices=(0, 1),
                                    help='set shutdown state')

    # -- ctl delport
    parser_ctl_delport = control_method.add_parser('delport',
                                                   help='delete port')
    parser_ctl_delport.add_argument('port', type=int,
                                    help='port number to delete')

    # -- ctl listport
    parser_ctl_listport = control_method.add_parser('listport',
                                                    help='show port list')

    # -- ctl setif
    parser_ctl_setif = control_method.add_parser('setif',
                                                 help='set interface config')
    parser_ctl_setif.add_argument('port', type=int,
                                  help='port number to set config')
    parser_ctl_setif.add_argument('--address',
                                  help='IPv4 address to set interface')
    parser_ctl_setif.add_argument('--netmask',
                                  help='IPv4 netmask to set interface')
    parser_ctl_setif.add_argument('--mtu', type=int,
                                  help='MTU to set interface')

    # -- ctl listif
    parser_ctl_listif = control_method.add_parser('listif',
                                                  help='show interface list')

    # -- ctl listfdb
    parser_ctl_listfdb = control_method.add_parser('listfdb',
                                                   help='show FDB entries')

    # -- go
    args = parser.parse_args()

    try:
        globals()['_start_' + args.subcommand](args)
    except Exception as e:
        _print_error({
            'code':    0 - 32603,
            'message': 'Internal error',
            'data':    '%s: %s' % (type(e).__name__, str(e)),
        })


if __name__ == '__main__':
    _main()
