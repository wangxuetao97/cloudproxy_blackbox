from base.rand import RandomNumber32, RandomNumber64, RandomString
from client.proxy_tcp_request import ProxyTcpRequest
from client.test_base import print_packet, TestStep, TestAction
from client.test_tcp import TestTcp
from client.test_udp import TestUdp
from packet.packet_types import service_type_map, make_ap_req
from packet.packer import pack, unpack, get_packet_size
from bitstring import BitStream

import logging
from socket import inet_pton, AF_INET

logging.basicConfig(format='[%(levelname)s %(asctime)s,'\
                    '%(funcName)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO)

def test_recv_packet():
    req = ProxyTcpRequest()
    req.connect('127.0.0.1', 30010)
    packet_bytes = req.recv_packet()
    req.close()
    print_packet(packet_bytes)

def test_send_recv_packet():
    req = ProxyTcpRequest()
    req.connect('127.0.0.1', 50001)
    req.make_packet(1)
    req.packet.version = 0
    req.packet.sid = RandomString()
    req.packet.detail = {}
    req.pack()
    req.send()
    packet_bytes = req.recv_packet()
    req.close()

def test_send_recv_full_packet():
    req = ProxyTcpRequest()
    req.connect('127.0.0.1', 50001)
    req.make_packet(8)
    req.packet.link_id = 1
    req.packet.payload = pack(make_ap_req())
    req.pack()
    req.send()
    packet_bytes = req.recv_packet()
    if packet_bytes is None:
        logging.info("Error: Empty packet.")
        return
    payload = req.recv_full_packet(packet_bytes)
    print_packet(payload)
    req.close()

def test_send_payload():
    req = ProxyTcpRequest()
    req.connect('127.0.0.1', 50001)
    req.make_packet(1)
    req.packet.version = 0
    req.packet.sid = RandomString()
    req.packet.detail = {}
    req.pack()
    req.send()
    req.recv_packet()
    req.make_packet(3)
    req.packet.request_id = 1
    req.packet.channel_type = 1
    req.packet.ip = int.from_bytes(inet_pton(AF_INET, '192.168.99.36'), 'big')
    req.packet.port = 25000
    req.pack()
    req.send()
    packet = unpack(BitStream(req.recv_packet()), service_type_map[5][4])
    link_id = packet.link_id
    logging.info("link_id: {}".format(link_id))
    req.make_packet(8)
    req.packet.link_id = link_id
    req.packet.payload = pack(make_ap_req())
    req.pack()
    req.send()
    packet_bytes = req.recv_packet()


def test_plan():
    tn = TestTcp('127.0.0.1', 50001, '192.168.99.36', 25000, 8000)
    tn.run()

def test_tcp_routine():
    tn = TestTcp('127.0.0.1', 50001, '192.168.99.36', 25000, 8000)
    tn.test_plan.append(TestStep(action=TestAction.CPJOIN))
    tn.test_plan.append(TestStep(action=TestAction.CPALLOCTCP, skip_step=2))
    tn.test_plan.append(TestStep(action=TestAction.CPAPTESTTCP, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPWAITRELEASE, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPALLOCTCP, skip_step=2))
    tn.test_plan.append(TestStep(action=TestAction.CPAPTESTTCP, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPWAITRELEASE, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPALLOCUDP, skip_step=1))
    tn.test_plan.append(TestStep(action=TestAction.CPAPTESTUDP, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPPING, wait=0))
    tn.start_test()
    tn.check_statistics()

def test_tls_routine():
    tn = TestTcp('127.0.0.1', 50002, '192.168.99.36', 25000, 8000, tls=True)
    tn.test_plan.append(TestStep(action=TestAction.CPJOIN))
    tn.test_plan.append(TestStep(action=TestAction.CPALLOCTCP, skip_step=2))
    tn.test_plan.append(TestStep(action=TestAction.CPAPTESTTCP, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPWAITRELEASE, wait=0))
    tn.test_plan.append(TestStep(action=TestAction.CPPING, wait=0))
    tn.start_test()
    tn.check_statistics()
    
def test_udp_routine():
    tn = TestUdp('127.0.0.1', 8001, '192.168.99.36', 8000)
    tn.test_plan.append(TestStep(action=TestAction.CPJOIN))
    tn.test_plan.append(TestStep(action=TestAction.CPAPTESTUDP))
    tn.test_plan.append(TestStep(action=TestAction.CPQUIT))
    tn.start_test()
    tn.check_statistics()
