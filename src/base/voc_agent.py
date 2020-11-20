# -*- coding: utf-8 -*-

import socket
import logging

from base.tcp_client import TcpClient
from packet.packet_types import VocJoinReq, VocJoinRes
from packet.packer import pack, unpack
from bitstring import BitStream

def unpack_callback(data):
    buffers = BitStream(data)
    res = unpack(buffers, VocJoinRes)
    return res != None, res

class VocAgent:
    def __init__(self, path):
        self.path = path
        self.tcp_clients = []
        ips = self.get_voc_ips()
        if ips is None:
            logging.warning("empty voc ips")
            return None
        for ip in ips:
            client = TcpClient(ip, 2000, unpack_callback)
            client.connect()
            if client.valid_socket():
                self.tcp_clients.append(client)

    def send_join(self):
        if len(self.tcp_clients) == 0:
            logging.warning("None tcp client avaliable")
            return None

        req = VocJoinReq()
        req.service_type = 0
        req.uri = 1
        req.path = self.path
        req.fro = 0
        req.ip = socket.htonl(0)
        req.port = socket.htons(0)

        for c in self.tcp_clients:
            data = pack(req)
            c.send_data(data)
            res = c.recv_short_data()
            if res is not None:
                logging.info("get join voc reply, code: {} with idc {}".format(res.code, res.config['idc']))
                return res
        return None


    def get_voc_ips(self):
        try:
            _, _ , ips = socket.gethostbyname_ex("center.voice.agora.com")
        except Exception as e:
            logging.warning("voc host resolve fail: {0}".format(e))
            return
        return ips



