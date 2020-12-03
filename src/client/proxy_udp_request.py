from bitstring import BitStream

import socket
import logging
import bitstring
import traceback

from packet.packer import pack, unpack
from packet.packet_types import udp_proxy_uri_packets, PROXY_UDP_SERVTYPE
 
class ProxyUdpRequest:
    def __init__(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.settimeout(5)
        except socket.error as err:
            self._socket = None
            err_info = "udp socket creation error:{0}\n".format(err)
            logging.warning(err_info)
        self._remote_ip = None # filled in set_remote()

    @property
    def packet(self):
        return self._packet

    def set_packet(self, packet):
        self._packet = packet

    def make_packet(self, uri): 
        self._packet = udp_proxy_uri_packets[uri]()
        self._packet.service_type = PROXY_UDP_SERVTYPE
        self._packet.uri = uri

    def set_remote(self, ip, port):
        self._remote_ip = ip
        self._remote_port = port
    
    def set_header(self, conn_id, ip, port):
        _conn_id = bitstring.pack('uintle:32', conn_id).read('bytes')
        # UDP header uses network order - big endian
        _ip_bytes = socket.inet_pton(socket.AF_INET, ip)
        _port_bytes = bitstring.pack('uintbe:16', port).read('bytes')
        self._header_bytes = _conn_id + _ip_bytes + _port_bytes

    def pack(self):
        self._data = self._header_bytes + pack(self._packet)

    def send(self):
        if not self.valid_socket():
            return
        logging.debug("<<<<< sending")
        logging.debug("length: {}".format(len(self._data)))
        logging.debug(self._data)
        try:
            sent = self._socket.sendto(self._data, (self._remote_ip, self._remote_port))
            if (sent != len(self._data)):
                err_info = "udp sent not complete to {1}".format(self._remote_ip)
                logging.warning(err_info)
        except Exception as e:
            self.close()
            err_info = "udp send error to {2}: {1}".format(e, self._remote_ip)
            logging.warning(err_info)

    def recv_packet(self):
        if self._socket is None:
            return None
        try: 
            res = self._socket.recv(4096)
        except Exception as e:
            self.close()
            err_info = "UDP Read packet error: {}".format(e)
            logging.warning(err_info)
            return None
        if len(res) < 13:
            err_info = "UDP Read packet too small, len: {}".format(len(res))
            logging.warning(err_info)
            return None
        logging.debug(">>>>> receiving")
        logging.debug("length: {}".format(len(res)))
        logging.debug(res)
        return res

    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def valid_socket(self):
        return self._socket != None
