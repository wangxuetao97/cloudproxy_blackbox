from abc import ABCMeta, abstractmethod
from bitstring import BitStream
from re import search

import socket
import ssl
import logging
import bitstring
import traceback

from client.test_base import print_packet
from packet.packer import pack, unpack, get_packet_size, get_serv_uri
from packet.packet_types import tcp_proxy_uri_packets, udp_proxy_uri_packets, PROXY_TCP_SERVTYPE, PROXY_UDP_SERVTYPE
 
class ProxyTcpRequest:
    def __init__(self):
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
            # switch to non-block mode
            self._socket.settimeout(5)
        except socket.error as err:
            self._socket = None
            err_info = "socket creation failed with error {0}\n".format(err)
            logging.warning(err_info)

    @property
    def packet(self):
        return self._packet
    
    def set_packet(self, packet):
        self._packet = packet

    def make_packet(self, uri):
        self._packet = tcp_proxy_uri_packets[uri]()
        self._packet.service_type = PROXY_TCP_SERVTYPE
        self._packet.uri = uri

    def pack(self):
        self._data = pack(self._packet)

    def connect(self, ip, port):
        if self._socket is None:
            return
        try:
            self._socket.connect((ip, port))
        except Exception as e:
            self.close()
            err_info = "Fail to connect to service: {0}:{1}\nwith err:{2}".format(ip, port, e)
            logging.warning(err_info)

    def send(self):
        if (self._socket is None):
            return
        logging.info("<<<<< sending")
        print_packet(self._data)
        totalsent = 0
        while totalsent < len(self._data):
            try:
                sent = self._socket.send(self._data[totalsent:])
                if (sent == 0):
                    break
                totalsent = totalsent + sent
            except:
                self.close()
                err_info = "tcp send data error:{0}".format(traceback.format_exc())
                logging.warning(err_info)
                break

    # return None when it cannot read packet header or socket error occurs.
    # return bytes read when socket closes.
    def recv_packet(self):
        if self._socket is None:
            return None
        chunks = []
        bytes_read = 0
        # assume there will be no empty packet
        while bytes_read < 3:
            try:
                chunk = self._socket.recv(3)
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_read += len(chunk)
            except Exception as e:
                self.close()
                err_info = "TCP Read packet head error: {}".format(e)
                logging.warning(err_info)
                return None
        # notice that head may be longer than 3 bytes
        head = b''.join(chunks)
        chunks.clear()
        chunks.append(head)
        packet_size, _ = get_packet_size(head)
        while bytes_read < packet_size:
            try:
                chunk = self._socket.recv(packet_size - len(head))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
            except Exception as e:
                self.close()
                err_info = "TCP Read packet error: {}".format(e)
                logging.warning(err_info)
                return None
        res = b''.join(chunks)
        logging.info(">>>>> receiving")
        print_packet(res)
        return res

    def get_payload(self, payload_packet_bytes):
        serv, uri = get_serv_uri(payload_packet_bytes)        
        packet = None
        if serv == PROXY_TCP_SERVTYPE:
            if uri == 7:
                packet = unpack(BitStream(payload_packet_bytes), tcp_proxy_uri_packets[7])
            elif uri == 8:
                logging.info('get_payload: {}'.format(payload_packet_bytes))
                packet = unpack(BitStream(payload_packet_bytes), tcp_proxy_uri_packets[8])
            else:
                logging.warning("Invalid payload packet uri in tcp proxy: {}".format(uri))
                return None
        else:
            logging.warning("Invalid payload packet service_id: {}".format(serv))
            return None
        if packet is None:
            logging.warning("Cannot unpack tcp payload packet.")
            return None
        return packet.payload

    # read full original packet from proxy's first payload packet
    # returns None if full payload packet cannot be read, from either closing or timeout.
    def recv_full_packet(self, first_packet_bytes):
        payload = self.get_payload(first_packet_bytes)
        if payload is None:
            return None
        # TODO assuming first payload will not be shorter than 3 bytes.
        size_needed, _ = get_packet_size(payload)
        if size_needed is None:
            logging.warning("Cannot read packet_size from payload")
            return None
        actual_size = len(payload)
        if size_needed < actual_size:
            logging.warning("First payload packet payload length corrupted. Needed: {}, actual: {}"\
                    .format(size_needed, actual_size))
            return None
        if size_needed == actual_size:
            logging.warning("Recv_full_packet: First packet is full packet.")
            return payload 
        # read remaining packets now
        while size_needed > actual_size:
            packet_bytes = self.recv_packet()
            if packet_bytes is None:
                return None
            # TODO no checking link_id here
            payload_new = self.get_payload(packet_bytes)
            # check it's right uri and format
            if payload_new is None:
                return None
            actual_size += len(payload_new)
            payload += payload_new
        if size_needed < actual_size:
            logging.warning("Payload actual size is larger than written size. Needed: {}, actual: {}"\
                    .format(size_needed, actual_size))
        return payload

    def close(self):
        if (self._socket != None):
            self._socket.close()
            self._socket = None

    def valid_socket(self):
        return self._socket != None


class ProxyTlsRequest(ProxyTcpRequest):
    def connect(self, ip, port):
        super().connect(ip, port)
        if self._socket is None:
            return
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            ssock = context.wrap_socket(self._socket, server_hostname="*.agora.io")
            logging.info(ssock.version())
        except Exception:
            logging.warning("ssl handshake error: {}".format(traceback.format_exc()))
            self.close()
            return
        self._socket = ssock


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

    # uri set to None to make a Udp Payload Packet
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
        logging.info("<<<<< sending")
        logging.info("length: {}".format(len(self._data)))
        logging.info(self._data)
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
        from client.test_base import print_packet
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
        logging.info(">>>>> receiving")
        logging.info("length: {}".format(len(res)))
        logging.info(res)
        return res

    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def valid_socket(self):
        return self._socket != None
