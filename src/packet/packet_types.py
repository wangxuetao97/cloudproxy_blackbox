from packet.typed.base import Descriptor, _descript
from packet.typed import Uint8, Uint16, Uint32, Uint64, Int32, String, Map, Vector, PacketBytes, RawBytes
from packet.utils import OrderedMeta
from base.rand import RandomString, RandomNumber32, RandomNumber64

from datetime import datetime
from bitstring import BitStream
import logging

VOC_SERVTYPE = 0
PROXY_TCP_SERVTYPE = 5
PROXY_UDP_SERVTYPE = 6

class EmptyPacket(object, metaclass=OrderedMeta):
    pass

class Packet(EmptyPacket):
    service_type = Uint16('service_type')
    uri = Uint16('uri')

class VocJoinReq(Packet):
    path = String('path')
    fro = Uint32("fro")
    ip = Uint32('ip')
    port = Uint16('port')
    info = String('info')

class VocJoinRes(Packet):
    code = Uint32('code')
    path = String('path')
    fro = Uint32('fro')
    ip = Uint32('ip')
    config = Map('config', key_type=String, mapped_type=String)

class TcpProxyJoinReq(Packet):
    version = Uint32('version')
    sid = String('sid')
    ticket = String('ticket')
    detail = Map('detail', key_type=Int32, mapped_type=String)

class TcpProxyJoinRes(Packet):
    code = Uint32('code')
    detail = Map('detail', key_type=Int32, mapped_type=String)

class AllocChannelReq(Packet):
    request_id = Uint32('request_id')
    channel_type = Uint8('channel_type')
    ip = Uint32('ip')
    port = Uint16('port')

class AllocChannelRes(Packet):
    request_id = Uint32('request_id')
    code = Uint16('code')
    link_id = Uint16('link_id')

class ReleaseChannelReq(Packet):
    link_id = Uint16('link_id')

class ChannelStatusPack(Packet):
    link_id = Uint16('link_id')
    status = Uint16('status')
    detail = String('detail')

class UdpDataPack(Packet):
    ip = Uint32('ip')
    port = Uint16('port')
    link_id = Uint16('link_id')
    payload = PacketBytes('payload')

class TcpDataPack(Packet):
    link_id = Uint16('link_id')
    payload = PacketBytes('payload')

class PingPack(Packet):
    ts = Uint64('ts') 

class PongPack(Packet):
    ts = Uint64('ts') 

class UdpProxyJoinReq(Packet):
    version = Uint32('version')
    sid = String('sid')
    ticket = String('ticket')
    token = String('token')
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class UdpProxyJoinRes(Packet):
    code = Uint32('code')
    connection_id = Uint32('connection_id')
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class UdpProxyReset(Packet):
    code = Uint32('code')
    connection_id = Uint32('connection_id')
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class UdpProxyQuit(Packet):
    pass

class UdpProxyPing(Packet):
    ts = Uint64('ts')    
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class UdpProxyPong(Packet):
    ts = Uint64('ts')
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class ChannelConfigPack(Packet):
    link_id = Uint16('link_id')
    detail = Map('detail', key_type=Int32, mapped_type=String)

class APv7JoinReq(Packet):
    request_env = Int32('request_env')
    sid = String('sid')
    flag = Uint32('flag')
    opid = Uint64('opid')
    uid = Uint32('uid')
    key = String('key')
    cname = String('cname')
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class APv7JoinRes(Packet):
    code = Uint32('code')
    flag = Uint32('flag')
    opid = Uint64('opid')
    env_id = Uint32('env_id')
    cid = Uint32('cid')
    uid = Uint32('uid')
    server_ts = Uint64('server_ts')
    cname = String('cname')
    addresses = Vector('addresses', value_type=String)
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class UniLbsRequest(Packet):
    flag = Uint32('flag')
    key = String('key')
    cname = String('cname')
    detail = Map('detail', key_type=Uint32, mapped_type=String)
    uid = Uint32('uid')

class EdgeServiceAddress(EmptyPacket):
    ip = Vector('ip', value_type=Uint8)
    port = Uint16('port')

@_descript(EdgeServiceAddress)
class EdgeServiceAddressDesc(Descriptor):
    pass

class UniLbsResponse(Packet):
    cid = Uint32('cid')
    uid = Uint32('uid')
    cname = String('cname')
    env = Uint8('env')
    cert = Vector('cert', value_type=Uint8)
    edge_services = Vector('edge_services', value_type=EdgeServiceAddressDesc)
    detail = Map('detail', key_type=Uint32, mapped_type=String)

class InnerBody(EmptyPacket):
    uri = Uint16('uri')
    buffer = PacketBytes('buffer')

@_descript(InnerBody)
class InnerBodyDesc(Descriptor):
    pass

class TestPac(EmptyPacket):
    bodies = Vector('bodies', value_type=InnerBodyDesc)

# serv 0 uri 74
class GenericRequest(Packet):
    sid = String('sid')
    opid = Uint64('opid')
    client_ts = Uint64('client_ts')
    appid = String('appid')
    real_address = Vector('real_address', value_type=Uint8)
    request_bodies = Vector('request_bodies', value_type=InnerBodyDesc)

# serv 0 uri 75
class GenericResponse(Packet):
    opid = Uint64('opid')
    flag = Uint32('flag')
    enter_ts = Uint64('enter_ts')
    leave_ts = Uint64('leave_ts')
    code = Uint32('code')
    wan_ip = Vector('wan_ip', value_type=Uint8)
    response_body = InnerBodyDesc('response_body')
    def __init__(self):
        self.__dict__['response_body'] = InnerBody()

def make_ap_req():
    # simulate ap_v7_env_req_single_service test
    req = APv7JoinReq()
    req.service_type = VOC_SERVTYPE
    req.uri = 67
    req.request_env = -1
    req.sid = ''
    req.flag = 1 << 2
    req.opid = 0
    req.uid = RandomNumber32()
    req.key = RandomString()
    req.cname = 'valid_cname'
    req.detail = {}
    return req

def check_ap_response(req, res) -> bool:
    if res.code != 0:
        return False
    if res.flag != 1:
        return False
    if res.cname != 'valid_cname':
        return False
    if res.uid != req.uid:
        return False
    return True

def make_ap_proxy_req(role):
    # simulate ap_generic_lbs_request
    from packet.packer import pack
    req = GenericRequest()
    req.service_type = VOC_SERVTYPE
    req.uri = 74
    req.sid = ''
    req.opid = RandomNumber64()
    req.client_ts = int(datetime.now().timestamp())
    req.appid = RandomString()
    req.real_address = []
    lbs_req = UniLbsRequest()
    lbs_req.service_type = VOC_SERVTYPE
    lbs_req.uri = 1
    if role == 'tcp':
        lbs_req.flag = 1 << 17 # kTcpProxy in external_protocol/base.h
    elif role == 'udp':
        lbs_req.flag = 1 << 16
    elif role == 'tls':
        lbs_req.flag = 1 << 18
    else:
        raise ValueError("Unknown role: {}".format(role))
    lbs_req.key = RandomString()
    lbs_req.cname = RandomString()
    lbs_req.uid = RandomNumber32()
    lbs_req.detail = {}
    ib = InnerBody()
    ib.uri = 1 # kUniLbsRequest in external_protocol/packet.h
    ib.buffer = pack(lbs_req) 
    req.request_bodies = [ib]
    return req

def read_ap_proxy_res(res: GenericResponse):
    from packet.packer import unpack
    from socket import inet_ntop, ntohs, AF_INET
    if res.service_type != 0 or res.uri != 75:
        logging.warning("ap proxy return error: {}".format(res.__dict__))
        return None
    ib:InnerBody = res.response_body
    if ib.uri != 2:
        logging.warning("ap proxy return wrong inner uri: {}".format(ib.uri))
        return None
    lbs_res:UniLbsResponse = unpack(BitStream(ib.buffer), UniLbsResponse)
    if len(lbs_res.edge_services) == 0:
        logging.warning("ap proxy return empty entry.")
        return None
    res = []
    for edge in lbs_res.edge_services: # pylint: disable=not-an-iterable
        # edge_ip is net order, edge_port is host order
        edge_ip = inet_ntop(AF_INET, bytes(edge.ip))
        if edge_ip is None or edge.port is None:
            continue
        res.append({"ip": edge_ip, "port": edge.port})
    return res

# tcp proxy: uri to packet types map
tcp_proxy_uri_packets = {
    1: TcpProxyJoinReq,
    2: TcpProxyJoinRes,
    3: AllocChannelReq,
    4: AllocChannelRes,
    5: ReleaseChannelReq,
    6: ChannelStatusPack,
    7: UdpDataPack,
    8: TcpDataPack,
    9: PingPack,
    10: PongPack,
    11: ChannelConfigPack,
}

# udp proxy: uri to packet types map
udp_proxy_uri_packets = {
    1: UdpProxyJoinReq,
    2: UdpProxyJoinRes,
    3: UdpProxyReset,
    4: UdpProxyPing,
    5: UdpProxyPong,
    6: UdpProxyQuit,
}

voc_uri_packet = {
    1: VocJoinReq,
    2: VocJoinRes,
    67: APv7JoinReq,
    68: APv7JoinRes,
    74: GenericRequest,
    75: GenericResponse,
}

# service_type to uri_packet_map map
service_type_map = {
    VOC_SERVTYPE: voc_uri_packet,
    PROXY_TCP_SERVTYPE: tcp_proxy_uri_packets, 
    PROXY_UDP_SERVTYPE: udp_proxy_uri_packets,
}
