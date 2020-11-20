from packet.typed.base import Descriptor, _typed, _fixed_bits, _unsigned
from bitstring import pack, BitStream

@_typed(int)
class Integer(Descriptor):
    pass

@_typed(float)
class Float(Descriptor):
    pass

@_typed(int)
@_unsigned
class UnsignedInteger(Descriptor):
    pass

@_typed(int)
@_unsigned
@_fixed_bits(32)
class Uint32(Descriptor):
    def get_bitstring(self, instance):
        # access own member from class member
        return pack('uintle:32', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('uintle:32'))


@_typed(int)
@_unsigned
@_fixed_bits(8)
class Uint8(Descriptor):
    def get_bitstring(self, instance):
        return pack('uintle:8', instance.__dict__.get(self.name, 0))
    
    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('uintle:8'))


@_typed(int)
@_unsigned
@_fixed_bits(16)
class Uint16(Descriptor):
    def get_bitstring(self, instance):
        return pack('uintle:16', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('uintle:16'))


@_typed(int)
@_unsigned
@_fixed_bits(64)
class Uint64(Descriptor):
    def get_bitstring(self, instance):
        return pack('uintle:64', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('uintle:64'))


@_typed(int)
@_fixed_bits(31)
class Int32(Descriptor):
    def get_bitstring(self, instance):
        return pack('intle:32', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('intle:32'))


@_unsigned
@_fixed_bits(7)
class Int8(Descriptor):
    def get_bitstring(self, instance):
        return pack('intle:8', instance.__dict__.get(self.name, 0))
    
    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('intle:8'))


@_typed(int)
@_fixed_bits(15)
class Int16(Descriptor):
    def get_bitstring(self, instance):
        return pack('intle:16', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('intle:16'))


@_typed(int)
@_fixed_bits(63)
class Int64(Descriptor):
    def get_bitstring(self, instance):
        return pack('intle:64', instance.__dict__.get(self.name, 0))

    def read_bitstring(self, buffer: BitStream, instance):
        self.__set__(instance, buffer.read('intle:64'))
