from bitstring import BitStream
from datetime import datetime
from socket import inet_ntop, AF_INET

import logging
import traceback
import time

from base.rand import RandomNumber32, RandomNumber64, RandomString
from client.test_base import TestBase, TestAction, TestStep, TestError, agolet_report, print_packet
from client.proxy_request import ProxyUdpRequest
from packet.packer import pack, unpack, get_packet_size, get_serv_uri
from packet.packet_types import udp_proxy_uri_packets, voc_uri_packet, make_ap_req, check_ap_response, VOC_SERVTYPE, PROXY_UDP_SERVTYPE 

# TODO fill port
CLOUDPROXY_UDP_PORT = 8001
AP_SERVER_IP = '192.168.99.36'
AP_SERVER_UDP_PORT = 8000
MAX_RETRY_COUNT = 3

class TestUdp(TestBase):
    def __init__(self, hostname):
        super().__init__('udp', hostname)
        self.link_id = None
        self.req = None
        self.last_ping_time = None
        self.last_payload = None
        self.step: TestStep = None

    def run(self):
        self.err_req_stat.reset()
        if not self.find_server_ip():
            return
        self.make_plan()
        self.print_plan()
        self.start_test()
        self.check_statistics()

    def start_test(self):
        logging.info("Test start")
        self.req = ProxyUdpRequest()
        if not self.req.valid_socket():
            self.record_err(TestError.CONNECT_PROXY_FAILED)
            return
        self.req.set_remote(self.server_ip, CLOUDPROXY_UDP_PORT)
        
        idx = 0
        try:
            while idx < len(self.test_plan):
                self.step = self.test_plan[idx]
                idx += 1
                logging.info("start step #{0}, wait {1} secs then do {2}.".format(idx, self.step.wait, self.step.action.name))
                if self.stop_event.wait(self.step.wait):
                    break
                if self.step.action == TestAction.CPJOIN:
                    self.req.make_packet(1)
                    self.req.packet.version = 0
                    self.req.packet.sid = RandomString()
                    self.req.packet.ticket = RandomString()
                    self.req.packet.token = RandomString()
                    self.req.packet.detail = {}
                    self.req.set_header(1, '127.0.0.1', 1)
                elif self.step.action == TestAction.CPPING:
                    if self.link_id is None:
                        logging.warning("Skip ping because no link id.")
                        continue
                    self.req.make_packet(4)
                    self.req.packet.ts = int(datetime.now().timestamp())
                    self.req.set_header(self.link_id, '127.0.0.1', 1)
                    self.last_ping_time = self.req.packet.ts
                elif self.step.action == TestAction.CPAPTESTUDP:
                    if self.link_id is None:
                        logging.warning("Skip ap test because no link id.")
                        continue
                    self.req.make_packet(None)
                    self.last_payload = make_ap_req()
                    self.req.packet.payload = pack(make_ap_req())[2:]
                    self.req.set_header(self.link_id, AP_SERVER_IP, AP_SERVER_UDP_PORT)
                elif self.step.action == TestAction.CPQUIT:
                    self.req.make_packet(6)
                    self.req.set_header(self.link_id, '127.0.0.1', 1)
                else:
                    logging.warning("Unknown test step in UDP proxy test.")
                    self.record_err(TestError.PYTHON_ERROR)
                # send and recv
                for retryidx in range(1, MAX_RETRY_COUNT + 1):
                    try:
                        packet_bytes = None
                        self.req.pack()
                        self.req.send()
                        self.err_req_stat.inc_total_cnt()
                        if self.step.action != TestAction.CPQUIT:
                            packet_bytes = self.req.recv_packet()
                        else:
                            break
                    except Exception:
                        self.req.close()
                        logging.warning("Exception in send, abort test:\n{}".format(traceback.format_exc()))
                        self.record_err(TestError.CONNECT_PROXY_FAILED)
                        return
                    if packet_bytes is not None:
                        break
                    if not self.req.valid_socket():
                        self.record_err(TestError.CONNECT_PROXY_FAILED)
                        return
                    if retryidx < MAX_RETRY_COUNT:
                        self.err_req_stat.inc_timeout_cnt()
                        time.sleep(1)
                action = self.handle_response(packet_bytes, self.step.action)
                if action < 0:
                    break
                idx += action
        except Exception:
            logging.warning("Exception in test:\n{}".format(traceback.format_exc()))
            self.record_err(TestError.PYTHON_ERROR)
        finally:
            logging.info("Close socket now.")
            self.req.close()
        logging.info("Test finish")
    
    def handle_response(self, raw_bytes, action) -> int:
        if raw_bytes is None:
            if action == TestAction.CPQUIT:
                return 0
            elif action == TestAction.CPPING:
                self.record_err(TestError.PING_FAILED)
                return 0
            else:
                self.record_err(TestError.PACKET_CORRUPTED)
                return -1
        
        # conn_id = int.from_bytes(raw_bytes[0:4], 'little')
        head_ip = inet_ntop(AF_INET, raw_bytes[4:8])
        # head_port = int.from_bytes(raw_bytes[8:10], 'big')
        packet_bytes = raw_bytes[10:]
        if head_ip == '127.0.0.1':
            serv, uri = get_serv_uri(packet_bytes)
            if serv != PROXY_UDP_SERVTYPE:
                self.record_err(TestError.PACKET_CORRUPTED)
                return -1
            if not (uri in udp_proxy_uri_packets):
                self.record_err(TestError.PACKET_CORRUPTED)
                return -1
            logging.info("packet bytes: {}".format(packet_bytes))
            packet = unpack(BitStream(packet_bytes), udp_proxy_uri_packets[uri])
            if packet is None:
                self.record_err(TestError.PACKET_CORRUPTED)
                return -1
            elif uri == 2:
                # Udp Join
                if packet.code != 0:
                    self.record_err(TestError.JOIN_FAILED)
                    return -1
                self.link_id = packet.connection_id
            elif uri == 3:
                # Udp Reset
                if packet.code == 2:
                    # illegal user
                    self.record_err(TestError.CONNECT_PROXY_FAILED)
                logging.warning("Udp connection get reset.")
                self.link_id = None
            elif uri == 5:
                # Udp Pong
                logging.info("Pong: {}, {}".format(packet.ts, datetime.fromtimestamp(packet.ts)))
            else:
                # handle invalid uri
                self.record_err(TestError.WRONG_URI_RETURN)
        else:
            if len(packet_bytes) > 12:
                logging.info(">>>>> get udp payload")
                print_packet(packet_bytes)
                return self.check_ap_payload(packet_bytes)                
            else:
                serv, uri = get_serv_uri(packet_bytes)
                if serv == PROXY_UDP_SERVTYPE and uri == 3:
                    packet = unpack(BitStream(packet_bytes), udp_proxy_uri_packets[3])
                    logging.warning("Udp connection get reset.")
                    self.link_id = None
                else:
                    self.record_err(TestError.PACKET_CORRUPTED)
                    return -1
        return 0
        
    def check_ap_payload(self, payload_bytes):
        serv, uri = get_serv_uri(payload_bytes)
        if serv != VOC_SERVTYPE or uri != 68:
            self.record_err(TestError.AP_ERROR)
            return 0
        apk = unpack(BitStream(payload_bytes), voc_uri_packet[68])
        if apk is None:
            self.record_err(TestError.UDP_PAYLOAD_CORRUPTED)
            return -1
        if not check_ap_response(self.last_payload, apk):
            self.record_err(TestError.AP_ERROR)
        return 0


                
            
