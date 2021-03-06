from bitstring import BitStream
from datetime import datetime
from socket import socket, gethostbyname, inet_pton, AF_INET, SOCK_STREAM

import logging
import time

from base.rand import RandomNumber32, RandomNumber64, RandomString
from client.test_base import TestBase, TestAction, TestStep, TestError,\
        agolet_report, print_packet, nslookup
from client.proxy_tcp_request import ProxyTcpRequest
from client.proxy_tls_request import ProxyTlsRequest
from packet.packer import pack, unpack, get_packet_size, get_serv_uri
from packet.packet_types import tcp_proxy_uri_packets, voc_uri_packet,\
        make_ap_proxy_req, read_ap_proxy_res, VOC_SERVTYPE, PROXY_TCP_SERVTYPE


class TestTcp(TestBase):
    def __init__(self, hostname, cp_port,\
                ap_host, ap_tcp_port, ap_udp_port, configs, tls=False):
        super().__init__('tcp' if tls == False else 'tls', hostname, configs)
        self.cp_port = cp_port
        self.ap_host = ap_host
        self.ap_tcp_port = ap_tcp_port
        self.ap_udp_port = ap_udp_port
        self.tcp_link_ids = []
        self.udp_link_ids = []
        self.req = None
        self.last_ping_time = 0 # set in start_test()
        self.last_payload = None # set in start_test()
        self.step: TestStep = None # set in start_test()

    # return False to exit, True to loop
    def run(self):
        self.err_req_stat.reset()
        self.ap_ip = nslookup(self.ap_host)
        if self.ap_ip is None:
            err_info = "Ap nslookup failed for: {}".format(self.ap_host)
            logging.error(err_info)
            return True
        self.make_plan()
        self.print_plan()
        self.start_test()
        self.check_statistics()
        if self.stop_event.is_set():
            return False
        else:
            return True
    
    def start_test(self):
        logging.info("Test start")
        if self.role == 'tcp':
            self.req = ProxyTcpRequest()
        elif self.role == 'tls':
            self.req = ProxyTlsRequest()
        else:
            raise ValueError('TestTcp: unknown role: {}'.format(self.role))
        self.err_req_stat.inc_total_cnt()
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
                logging.info("start step #{0}, wait {1} secs then do {2}."\
                        .format(idx, self.step.wait, self.step.action.name))
                if self.stop_event.wait(self.step.wait):
                    break
                # prepare content
                if self.step.action == TestAction.CPJOIN:
                    self.req.make_packet(1)
                    self.req.packet.version = 0
                    self.req.packet.sid = RandomString()
                    self.req.packet.detail = {2: '123456'}
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
                    self.last_payload = make_ap_proxy_req(self.role, self.configs.get("staging_env", False))
                    self.req.packet.payload = pack(self.last_payload)
                elif self.step.action == TestAction.CPAPTESTUDP:
                    if len(self.udp_link_ids) == 0:
                        logging.warning("Skip ap test because no active proxy channel.")
                        continue
                    self.req.make_packet(7)
                    self.req.packet.ip = int.from_bytes(inet_pton(AF_INET, self.ap_ip), 'big')
                    self.req.packet.port = self.ap_udp_port
                    self.req.packet.link_id = self.udp_link_ids[-1]
                    self.last_payload = make_ap_proxy_req(self.role, self.configs.get("staging_env", False))
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
                elif self.step.action == TestAction.CPCONFIGVID:
                    self.req.make_packet(11)
                    self.req.packet.link_id = 0xffff
                    self.req.packet.detail = {11: "123456"}
                else:
                    logging.warning("Unknown test step in TCP proxy test.")
                    self.record_err(TestError.PYTHON_ERROR)
                # send and recv
                if not self.req.valid_socket():
                    logging.warning("Invalid tcp socket")
                    self.record_err(TestError.CONNECT_PROXY_FAILED)
                    return
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
                action = self.handle_response(packet_bytes, self.step.action)
                if action < 0:
                    logging.warning(
                            "Response handler says abort test with error code {}"
                            .format(action))
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

    def check_ap_fail(self, tcp) -> bool:
        ap_socket = socket(AF_INET, SOCK_STREAM)
        ap_socket.settimeout(5)
        try:
            if tcp:
                ap_socket.connect((self.ap_ip, self.ap_tcp_port))
            else:
                ap_socket.connect((self.ap_ip, self.ap_udp_port))
        except:
            ap_socket.close()
            return True
        return False

    def handle_ap_fail(self, tcp) -> bool:
        logging.info("Handle ap fail called")
        if self.check_ap_fail(tcp):
            self.record_err(TestError.AP_ERROR)
            if self.configs.get("ignore_ap_fail", False):
                logging.warning("AP fail ignored on {}".format(self.ap_ip))
            else:
                agolet_report(self.agolet_ap_fail_msg(self.ap_ip))
            self.stop()
            return True
        else:
            return False

    def handle_response(self, packet_bytes, action) -> int:
        if packet_bytes is None:
            if action == TestAction.CPPING:
                self.record_err(TestError.PING_FAILED)
                return 0
            elif action == TestAction.CPWAITRELEASE:
                self.record_err(TestError.RELEASE_FAILED)
                return 0
            elif action == TestAction.CPALLOCTCP:
                if not self.handle_ap_fail(True):
                    self.record_err(TestError.CONNECT_PROXY_FAILED)
                return -1
            else:
                self.record_err(TestError.CONNECT_PROXY_FAILED)
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
                if (action == TestAction.CPALLOCTCP \
                        and self.handle_ap_fail(True)) or \
                   (action == TestAction.CPALLOCUDP \
                        and self.handle_ap_fail(False)):
                    self.stop()
                    return -1
                else:
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
            if packet.link_id != 0xffff \
                    and packet.link_id not in self.tcp_link_ids \
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
                elif action == TestAction.CPCONFIGVID:
                    pass
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
