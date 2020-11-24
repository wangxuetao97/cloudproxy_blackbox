from packet.packet_types import Packet, EmptyPacket
from packet.typed.base import Descriptor
from bitstring import BitStream, BitString, pack as bpack

import logging

def total_byte_size(pkt: Packet) -> int:
    res = 0
    for attr in pkt._order():
        res += getattr(pkt.__class__, attr).get_length(pkt)

    return res + 2

def pack(pkt: Packet) -> bytes:
    vec = []
    length = 0
    for attr in pkt._order():
        if isinstance(getattr(pkt.__class__, attr), Descriptor):
            # descriptor needs one declaration as class member
            bit = getattr(pkt.__class__, attr).get_bitstring(pkt)
            vec.append(bit)
            length += len(bit) / 8
        else:
            # non-descriptor sub-packet needs two declarations as class member and self member.
            # their packed result will not have a length header.
            sub_packet = pkt.__dict__[attr]
            for sub_attr in sub_packet._order():
                sub_bit = getattr(sub_packet.__class__, sub_attr).get_bitstring(sub_packet)
                vec.append(sub_bit)
                length += len(sub_bit) / 8

    res = bpack('uintle:16', length + 2)
    for content in vec:
        res += content
    return res.tobytes()


def unpack(buffer: BitStream, tp) -> Packet:
    res = tp()
    try:
        byte_length = buffer.read('uintle:16')
    except Exception as e:
        logging.warning(e)
        return None
    assert byte_length * 8 == len(buffer)
    for attr in res._order():
        if (isinstance(getattr(tp, attr), Descriptor)):
            getattr(tp, attr).read_bitstring(buffer, res)
        else:
            sub_res = getattr(tp, attr)
            for sub_attr in sub_res._order():
                getattr(sub_res, sub_attr).read_bitstring(buffer, sub_res)
    return res

def get_packet_size(buffer: bytes):
    if len(buffer) < 3:
        return None, None
    packet_size = buffer[0] + (buffer[1] << 8)
    if buffer[1] > 0x80:
        packet_size = (packet_size & 0x7fff) + (buffer[2] << 15)
        return packet_size, 3
    else:
        return packet_size, 2

def get_serv_uri(buffer: bytes):
    if len(buffer) < 7:
        return None, None
    _, head_size = get_packet_size(buffer)
    service_id = buffer[head_size] + (buffer[head_size + 1] << 8)
    uri = buffer[head_size + 2] + (buffer[head_size + 3] << 8)
    return service_id, uri