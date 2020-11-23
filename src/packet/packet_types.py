from packet.typed import Uint8, Uint16, Uint32, Uint64, Int32, String, Map, Vector, PacketBytes, RawBytes
from packet.utils import OrderedMeta
from base.rand import RandomString, RandomNumber32

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

def make_ap_req():
    # simulate ap_v7_env_req_single_service test
    req = APv7JoinReq()
    req.service_type = VOC_SERVTYPE
    req.uri = 67
    req.request_env = -1
    req.sid = ''
    req.flag = 1 << 17
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
}

# service_type to uri_packet_map map
service_type_map = {
    VOC_SERVTYPE: voc_uri_packet,
    PROXY_TCP_SERVTYPE: tcp_proxy_uri_packets, 
    PROXY_UDP_SERVTYPE: udp_proxy_uri_packets,
}
