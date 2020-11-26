def add_merge(d1, d2):
    for key, value in d2.items():
        if d1.__contains__(key):
            d1[key] += value
        else:
            d1[key] = value


class QualityCollector:
    def __init__(self):
        self.count = 0
        self.got = 0
        self.map = {}

    def set_count(self, count):
        self.count = count
    
    def put(self, err_map):
        self.got += 1
        add_merge(self.map, err_map)
    
    def ready(self):
        return self.got >= self.count
    
    def move(self):
        tmp = self.map
        self.map = {}
        return tmp

class Collectors:
    cp_collector = QualityCollector()
