from packet.typed.base import _typed, Descriptor
from bitstring import pack, BitStream


def _vector(cls):
    super_set = cls.__set__

    class TyppedVector(list):
        def __init__(self, value_type):
            self._value_type = value_type

            super().__init__()

        def _value_check(self, value):
            class TempChecker:
                checker = self._value_type('checker')

            checker = TempChecker()
            checker.checker = value

        def __setitem__(self, key, value):
            self._value_check(value)
            return super().__setitem__(key, value)

        def append(self, value):
            self._value_check(value)
            return super().append(value)

    def __set__(self, instance, vec_value):
        v = TyppedVector(self.value_type)

        for value in vec_value:
            v.append(value)

        super_set(self, instance, v)

    cls.__set__ = __set__

    return cls


@_typed(list)
@_vector
class Vector(Descriptor):
    def __init__(self, name, **args):
        if 'value_type' not in args:
            raise TypeError("expect 'value_type' in args")
        super().__init__(name, **args)

    def get_length(self, instance):
        return len(instance.__dict__.get(self.name, []))

    def get_bitstring(self, instance):
        def _value_bit(self, value):
            class TempChecker:
                checker = self.value_type('checker')

            checker = TempChecker()
            checker.checker = value
            return TempChecker.checker.get_bitstring(checker)

        res = pack('uintle:16', self.get_length(instance))
        for value in instance.__dict__.get(self.name, {}):
            res += _value_bit(self, value)
        return res

    def read_bitstring(self, buffer: BitStream, instance):
        def _key_bit(self):
            class TempChecker:
                checker = self.value_type('checker')

            checker = TempChecker()
            TempChecker.checker.read_bitstring(buffer, checker)
            return checker.checker

        size = buffer.read('uintle:16')

        self.__set__(instance, [])

        for i in range(size):
            kv = _key_bit(self)

            instance.__dict__[self.name].append(kv)

