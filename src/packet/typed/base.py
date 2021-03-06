from bitstring import BitStream

"""
Descriptor resembles C type.
Descriptors should be static class members.
It rewrites __set__ function. 
Setting a value to a Descriptor will set to a member variable of 'self' with the same name.
_typed, _unsigned and _fixed encapsulates this setter to conform C restrictions.
"""
class Descriptor:
    """
    Base class which all injectors will injected into
    """
    def __init__(self, name: str, **args):
        self.name = name
        for key, value in args.items():
            setattr(self, key, value)

    # set to own member without overwrite itself 
    def __set__(self, instance, value):
        instance.__dict__[self.name] = value


# generate descriptor from sub-packet value type
def _descript(value_type: type, cls=None):
    if cls is None:
        return lambda cls: _descript(value_type, cls)
    def get_length(self, instance):
        val_obj = instance.__dict__[self.name]
        res = 0
        for attr in val_obj._order():
            res += getattr(value_type, attr).get_length(val_obj)
        return res
    def get_bitstring(self, instance):
        val_obj = instance.__dict__[self.name]
        res = BitStream()
        for attr in val_obj._order():
            res += getattr(value_type, attr).get_bitstring(val_obj)
        return res
    def read_bitstring(self, buf: BitStream, instance):
        self.__set__(instance, value_type())
        val_obj = instance.__dict__[self.name]
        for attr in val_obj._order():
            getattr(value_type, attr).read_bitstring(buf, val_obj)
    cls = _typed(value_type, cls)
    cls.get_length = get_length
    cls.get_bitstring = get_bitstring
    cls.read_bitstring = read_bitstring
    return cls


def _typed(expected_type: type, cls=None):
    """
    inject type check into cls

    :return cls
    """

    if cls is None:
        return lambda cls: _typed(expected_type, cls)

    super_set = cls.__set__

    def __set__(self, instance, value):
        if not isinstance(value, expected_type):
            raise TypeError(
                    '[Typed] expect {0}, but {1} found'.format(expected_type, type(value)))

        super_set(self, instance, value)

    cls.__set__ =  __set__
    return cls


def _unsigned(cls):
    """
    inject unsinged check for integer

    :return cls
    """

    super_set = cls.__set__

    def __set__(self, instance, value):
        if value < 0:
            raise ValueError('[Unsigned] value should be >= 0')
        super_set(self, instance, value)

    cls.__set__ = __set__
    return cls


def _fixed_bits(size, cls=None):
    """
    inject fixed size check for integer

    :return cls
    """

    if cls is None:
        return lambda cls: _fixed_bits(size, cls)

    super_set = cls.__set__

    max_value = 2 ** size
    min_value = -max_value

    def get_length(cls, instance):
        return int(size / 8)

    def __set__(self, instance, value):
        if not (min_value < value < max_value):
            raise ValueError('[FixedBits] value overflow')

        super_set(self, instance, value)

    cls.__set__ = __set__
    cls.get_length = get_length

    return cls

