from bitstring import BitStream

from packet.typed.base import _typed, Descriptor
from packet.typed.integer import Uint8, Uint16, Uint32, Uint64, Int8, Int16, Int32, Int64, Float
from packet.typed.kvmap import Map
from packet.typed.vector import Vector


@_typed(str)
class String(Descriptor):
    def get_length(self, instance):
        return len(instance.__dict__.get(self.name, ''))

    def get_bitstring(self, instance):
        from bitstring import pack
        res = pack('uintle:16', len(instance.__dict__.get(self.name, '')))
        for ch in instance.__dict__.get(self.name, ''):
            res += pack('uintle:8', ord(ch))
        return res

    def read_bitstring(self, buffer: BitStream, instance):
        size = buffer.read('uintle:16')
        res = ''
        for _ in range(size):
            res += chr(buffer.read('uintle:8'))
        self.__set__(instance, res)


@_typed(bytes)
class PacketBytes(Descriptor):
    def get_length(self, instance):
        return len(instance.__dict__.get(self.name, ''))
    
    def get_bitstring(self, instance):
        from bitstring import pack
        target = instance.__dict__.get(self.name, '')
        res = pack('uintle:16', len(target)) + target
        return res
    
    def read_bitstring(self, buffer: BitStream, instance):
        from bitstring import pack
        content_len = buffer.read('uintle:16')
        content = buffer.read('bytes:' + str(content_len))
        self.__set__(instance, content)

@_typed(bytes)
class RawBytes(Descriptor):
    def get_length(self, instance):
        return len(instance.__dict__.get(self.name, ''))
    
    def get_bitstring(self, instance):
        return BitStream(instance.__dict__.get(self.name, ''))
    
    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('bytes'))


__all__ = ['String', 'PacketBytes', 'RawBytes',
           'Uint8', 'Uint16', 'Uint32', 'Uint64',
           'Int8', 'Int16', 'Int32', 'Int64',
           'Map', 'Vector', 'Float'
           ]

