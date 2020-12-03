from bitstring import BitStream
from datetime import datetime
from socket import gethostbyname, inet_pton, AF_INET

import logging
import time

from base.rand import RandomNumber32, RandomNumber64, RandomString
from client.test_base import TestBase, TestAction, TestStep, TestError, agolet_report, print_packet
from client.proxy_tcp_request import ProxyTcpRequest
from client.proxy_tls_request import ProxyTlsRequest
from packet.packer import pack, unpack, get_packet_size, get_serv_uri
from packet.packet_types import tcp_proxy_uri_packets, voc_uri_packet, make_ap_proxy_req, read_ap_proxy_res, VOC_SERVTYPE, PROXY_TCP_SERVTYPE

MAX_RETRY_COUNT = 1

class TestTcp(TestBase):
    def __init__(self, hostname, cp_port, ap_ip, ap_tcp_port, ap_udp_port, tls=False):
        super().__init__('tcp' if tls == False else 'tls', hostname)
        self.cp_port = cp_port
        self.ap_ip = ap_ip
        self.ap_tcp_port = ap_tcp_port
        self.ap_udp_port = ap_udp_port
        self.tcp_link_ids = []
        self.udp_link_ids = []
        self.req = None
        self.last_ping_time = 0 # set in start_test()
        self.last_payload = None # set in start_test()
        self.step: TestStep = None # set in start_test()

    def run(self):
        self.err_req_stat.reset()
        self.make_plan()
        self.print_plan()
        self.start_test()
        self.check_statistics()
    
    def start_test(self):
        logging.info("Test start")
        if self.role == 'tcp':
            self.req = ProxyTcpRequest()
        elif self.role == 'tls':
            self.req = ProxyTlsRequest()
        else:
            raise ValueError('TestTcp: unknown role: {}'.format(self.role))
        self.req.connect(self.server_ip, self.cp_port)
        if not self.req.valid_socket():
            # connect failure handle
            self.record_err(TestError.CONNECT_PROXY_FAILED)
            return
        
        idx = 0
        try:
            while idx < len(self.test_plan):
                self.step = self.test_plan[idx]
                idx += 1
                logging.info("start step #{0}, wait {1} secs then do {2}.".format(idx, self.step.wait, self.step.action.name))
                if self.stop_event.wait(self.step.wait):
                    break
                # prepare content
                if self.step.action == TestAction.CPJOIN:
                    self.req.make_packet(1)
                    self.req.packet.version = 0
                    self.req.packet.sid = RandomString()
                    self.req.packet.detail = {}
                elif self.step.action == TestAction.CPALLOCTCP \
                        or self.step.action == TestAction.CPALLOCUDP:
                    self.req.make_packet(3)
                    self.req.packet.request_id = 1
                    if self.step.action == TestAction.CPALLOCTCP:
                        self.req.packet.channel_type = 1
                        self.req.packet.ip = int.from_bytes(inet_pton(AF_INET, self.ap_ip), 'big')
                        self.req.packet.port = self.ap_tcp_port
                    else:
                        self.req.packet.channel_type = 2
                elif self.step.action == TestAction.CPAPTESTTCP:
                    if len(self.tcp_link_ids) == 0:
                        logging.warning("Skip ap test because no active proxy channel.")
                        continue
                    self.req.make_packet(8)
                    self.req.packet.link_id = self.tcp_link_ids[-1]
                    self.last_payload = make_ap_proxy_req(self.role)
                    self.req.packet.payload = pack(self.last_payload)
                elif self.step.action == TestAction.CPAPTESTUDP:
                    if len(self.udp_link_ids) == 0:
                        logging.warning("Skip ap test because no active proxy channel.")
                        continue
                    self.req.make_packet(7)
                    self.req.packet.ip = int.from_bytes(inet_pton(AF_INET, self.ap_ip), 'big')
                    self.req.packet.port = self.ap_udp_port
                    self.req.packet.link_id = self.udp_link_ids[-1]
                    self.last_payload = make_ap_proxy_req(self.role)
                    self.req.packet.payload = pack(self.last_payload)
                elif self.step.action == TestAction.CPRELEASETCP:
                    if len(self.tcp_link_ids) == 0:
                        logging.warning("Skip TCP channel release because no active proxy channel.")
                        continue
                    self.req.make_packet(5)
                    self.req.packet.link_id = self.tcp_link_ids[-1]
                elif self.step.action == TestAction.CPRELEASEUDP:
                    if len(self.udp_link_ids) == 0:
                        logging.warning("Skip UDP channel release because no active proxy channel.")
                        continue
                    self.req.make_packet(5)
                    self.req.packet.link_id = self.udp_link_ids[-1]
                elif self.step.action == TestAction.CPPING:
                    self.req.make_packet(9)
                    self.req.packet.ts = int(datetime.now().timestamp()) 
                    self.last_ping_time = self.req.packet.ts
                elif self.step.action == TestAction.CPWAITRELEASE:
                    pass
                else:
                    logging.warning("Unknown test step in TCP proxy test.")
                    self.record_err(TestError.PYTHON_ERROR)
                # send and recv
                for retryidx in range(1, MAX_RETRY_COUNT + 1):
                    try:
                        self.err_req_stat.inc_total_cnt()
                        if self.step.action != TestAction.CPWAITRELEASE:
                            self.req.pack()
                            self.req.send()
                        packet_bytes = self.req.recv_packet()
                    except Exception as e:
                        self.req.close()
                        logging.warning("Exception in send, abort test: {}".format(e))
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
                    # handle_response says abort test
                    break
                # handle_response says skip next <action> steps
                idx += action
        except Exception as e:
            logging.warning("Exception in test: {}".format(e))
            self.record_err(TestError.PYTHON_ERROR)
        finally:
            logging.info("Close socket now.")
            self.req.close()
        logging.info("Test finish")
    
    def handle_response(self, packet_bytes, action) -> int:
        if packet_bytes is None:
            if action == TestAction.CPPING:
                self.record_err(TestError.PING_FAILED)
                return 0
            elif action == TestAction.CPWAITRELEASE:
                self.record_err(TestError.RELEASE_FAILED)
                return 0
            else:
                self.record_err(TestError.PACKET_CORRUPTED)
                return -1

        # corrupted packet always leads to test abortion
        service_id, uri = get_serv_uri(packet_bytes)
        if service_id != PROXY_TCP_SERVTYPE:
            self.record_err(TestError.PACKET_CORRUPTED)
            return -1
        if not (uri in tcp_proxy_uri_packets):
            self.record_err(TestError.PACKET_CORRUPTED)
            return -1
        packet = unpack(BitStream(packet_bytes), tcp_proxy_uri_packets[uri])
        if packet is None:
            self.record_err(TestError.PACKET_CORRUPTED)
            return -1
        if uri == 2:
            # Join Proxy Res
            if action != TestAction.CPJOIN:
                self.record_err(TestError.UNEXPECTED_PACKET)
            if packet.code != 0:
                self.record_err(TestError.JOIN_FAILED)
                return -1
        elif uri == 4:
            # Alloc Channel Res
            if action != TestAction.CPALLOCTCP \
                    and action != TestAction.CPALLOCUDP:
                self.record_err(TestError.UNEXPECTED_PACKET)
            if packet.code != 0:
                self.record_err(TestError.ALLOC_FAILED)
                if self.step.skip_step is None:
                    return 2
                else:
                    return self.step.skip_step
            if action == TestAction.CPALLOCTCP:
                self.tcp_link_ids.append(packet.link_id)
            else:
                self.udp_link_ids.append(packet.link_id)
        elif uri == 6:
            # Channel Status
            # errcode: 
            # Release ok: 0
            # Illegal User: 2
            # Udp link not exist: 4
            # Tcp link not exist: 5
            # Release fail: 6
            # Channel config fail: 7
            if packet.link_id not in self.tcp_link_ids \
                    and packet.link_id not in self.udp_link_ids:
                self.record_err(TestError.WRONG_LINKID_RETURN)
                return -1
            if packet.status == 0:
                if action == TestAction.CPRELEASETCP:
                    if packet.link_id not in self.tcp_link_ids:
                        self.record_err(TestError.WRONG_LINKID_RETURN)
                        return -1
                    self.tcp_link_ids.remove(packet.link_id)
                elif action == TestAction.CPRELEASEUDP:
                    if packet.link_id not in self.udp_link_ids:
                        self.record_err(TestError.WRONG_LINKID_RETURN)
                        return -1
                    self.udp_link_ids.remove(packet.link_id)
                else:
                    self.record_err(TestError.UNEXPECTED_PACKET)
            elif packet.status == 6:
                if action == TestAction.CPRELEASETCP \
                        or action == TestAction.CPRELEASEUDP:
                    self.record_err(TestError.RELEASE_FAILED)
                else:
                    self.record_err(TestError.UNEXPECTED_PACKET)
            elif (packet.status == 4 or packet.status == 5):
                if action != TestAction.CPWAITRELEASE:
                    logging.warning("Unexpected proxy channel close: {}".format(packet.link_id))
                    self.record_err(TestError.UNEXPECTED_CHANNEL_CLOSED)
                    # because test steps may go wrong, abort now.
                    return -1
                if packet.status == 4:
                    self.udp_link_ids.remove(packet.link_id)
                else:
                    self.tcp_link_ids.remove(packet.link_id)
            elif packet.status == 2:
                self.record_err(TestError.CONNECT_PROXY_FAILED)
                return -1
            elif packet.status == 7:
                self.record_err(TestError.CONFIG_CHANNEL_FAILED)
            else:
                self.record_err(TestError.UNEXPECTED_PACKET)
        elif uri == 7:
            # Udp Data Pack
            payload_bytes = self.req.recv_full_packet(packet_bytes)
            if payload_bytes is None:
                self.record_err(TestError.UDP_PAYLOAD_CORRUPTED)
                # hard to figure out the proxy channel state, so abort test now.
                return -1
            logging.debug(">>>>> get udp payload")
            print_packet(payload_bytes)
            return self.check_ap_payload(payload_bytes)
        elif uri == 8:
            # Tcp Data Pack
            payload_bytes = self.req.recv_full_packet(packet_bytes)
            if payload_bytes is None:
                self.record_err(TestError.TCP_PAYLOAD_CORRUPTED)
                # hard to figure out the proxy channel state, so abort test now.
                return -1
            logging.debug(">>>>> get tcp payload")
            print_packet(payload_bytes)
            return self.check_ap_payload(payload_bytes)
        elif uri == 10:
            # Pong Pack
            logging.debug("Pong: {}, {}".format(packet.ts, datetime.fromtimestamp(packet.ts)))
        else:
            # handle invalid uri
            self.record_err(TestError.WRONG_URI_RETURN)
        return 0

    def check_ap_payload(self, payload_bytes):
        pay_service_id, pay_uri = get_serv_uri(payload_bytes)
        if pay_service_id != VOC_SERVTYPE or pay_uri != 75:
            self.record_err(TestError.AP_ERROR)
            return 0
        payload_packet = unpack(BitStream(payload_bytes), voc_uri_packet[pay_uri])
        if payload_packet is None:
            self.record_err(TestError.TCP_PAYLOAD_CORRUPTED)
            return -1
        addrs = read_ap_proxy_res(payload_packet)
        if len(addrs) == 0:
            self.record_err(TestError.AP_ERROR)
        return 0
