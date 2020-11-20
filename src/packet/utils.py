from collections import OrderedDict
from sys import modules

from packet.typed.base import Descriptor

class OrderedMeta(type):
    def __new__(cls, clsname, bases, clsdict):
        d = dict(clsdict)
        order = []

        for name, value in clsdict.items():
            if isinstance(value, Descriptor):
                value._name = name
                order.append(name)
            if clsname != "EmptyPacket" and clsname != "Packet":
                from packet.packet_types import EmptyPacket
                if isinstance(value, EmptyPacket):
                    value._name = name
                    order.append(name)

        def order_func(s):
            assert len(bases) <= 1
            if len(bases) == 1 and bases[0] is not object:
                return super(getattr(modules[clsdict['__module__']],
                 clsdict['__qualname__']), s)._order() + order

            return order

        d['_order'] = order_func
        return type.__new__(cls, clsname, bases, d)

    @classmethod
    def __prepare__(cls, clsname, bases):
        return OrderedDict()

def to_debug_string(pkt):
    res = []
    for item in pkt._order():
        res.append('{0}: {1}'.format(item, pkt.__dict__.get(item, None)))
    return ", ".join(res)


