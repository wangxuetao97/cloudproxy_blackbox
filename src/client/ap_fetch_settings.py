from client.proxy_tcp_request import ProxyTcpRequest

import packet.packet_types as pt
import packet.packer as pk
from bitstring import BitStream, pack

def ap_fetch_cp(role, ap_ip, ap_port):
    req = pt.make_ap_proxy_req(role)
    ptr = ProxyTcpRequest()
    ptr.connect(ap_ip, ap_port)
    ptr.set_packet(req)
    ptr.pack()
    ptr.send()
    pac = ptr.recv_packet()
    if pac is None:
        return None, None
    packet = pk.unpack(BitStream(pac), pt.GenericResponse)
    if packet is None:
        return None, None
    eip, eport = pt.read_ap_proxy_res(packet)
    return eip, eport

