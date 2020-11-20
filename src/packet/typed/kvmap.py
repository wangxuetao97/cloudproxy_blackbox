from packet.typed.base import Descriptor, _typed
from bitstring import pack, BitStream

def _mapped(cls):
    """
    inject size check for integer

    :return cls
    """
    class TyppedDict(dict):
        def __init__(self, key_type, mapped_type):
            self._key_type = key_type
            self._mapped_type = mapped_type

            super().__init__()

        def _key_check(self, value):
            class TempChecker:
                checker = self._key_type('checker')

            checker = TempChecker()
            checker.checker = value

        def _mapped_check(self, value):
            class TempChecker:
                checker = self._mapped_type('checker')

            checker = TempChecker()
            checker.checker = value

        def __setitem__(self, key, value):
            self._key_check(key)
            self._mapped_check(value)
            return super().__setitem__(key, value)

    super_set = cls.__set__

    def __set__(self, instance, dict_value):
        v = TyppedDict(self.key_type, self.mapped_type)

        for key, value in dict_value.items():
            v[key] = value

        super_set(self, instance, v)

    cls.__set__ = __set__

    return cls


@_typed(dict)
@_mapped
class Map(Descriptor):
    def __init__(self, name, **args):
        if 'key_type' not in args or 'mapped_type' not in args:
            raise TypeError("expect 'key_type' and 'mapped_type' in args")

        super().__init__(name, **args)

    def get_length(self, instance):
        return len(instance.__dict__.get(self.name, {}))

    def get_bitstring(self, instance):
        def _key_bit(self, value):
            class TempChecker:
                checker = self.key_type('checker')

            checker = TempChecker()
            checker.checker = value
            return TempChecker.checker.get_bitstring(checker)

        def _mapped_bit(self, value):
            class TempChecker:
                checker = self.mapped_type('checker')

            checker = TempChecker()
            checker.checker = value
            return TempChecker.checker.get_bitstring(checker)

        res = pack('uintle:16', self.get_length(instance))
        for key, value in instance.__dict__.get(self.name, {}).items():
            res += _key_bit(self, key)
            res += _mapped_bit(self, value)
        return res

    def read_bitstring(self, buffer: BitStream, instance):
        def _key_bit(self):
            class TempChecker:
                checker = self.key_type('checker')

            checker = TempChecker()
            TempChecker.checker.read_bitstring(buffer, checker)
            return checker.checker

        def _mapped_bit(self):
            class TempChecker:
                checker = self.mapped_type('checker')

            checker = TempChecker()
            TempChecker.checker.read_bitstring(buffer, checker)
            return checker.checker

        size = buffer.read('uintle:16')

        self.__set__(instance, {})

        for i in range(size):
            kv = _key_bit(self)
            mv = _mapped_bit(self)

            instance.__dict__[self.name][kv] = mv
