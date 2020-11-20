# -*- coding:utf-8 -*-

class Statistics:
    def __init__(self):
        self.reset()

    def reset(self):
        self._timeout_cnt = 0
        self._err_cnt = 0
        self._total_cnt = 0

    @property
    def timeout_cnt(self):
        return self._timeout_cnt

    @property
    def err_cnt(self):
        return self._err_cnt

    @property
    def total_cnt(self):
        return self._total_cnt

    @property
    def timeout_rate(self):
        return 0 if self.total_cnt == 0 else self.timeout_cnt / self.total_cnt

    @property
    def err_rate(self):
        return 0 if self.total_cnt == 0 else self.err_cnt / self.total_cnt

    @property
    def success_rate(self):
        return 1 - self.err_rate

    @property
    def abnormal_count(self):
        return self.err_cnt + self.timeout_cnt

    def inc_timeout_cnt(self):
        self._timeout_cnt += 1

    def inc_err_cnt(self):
        self._err_cnt += 1

    def inc_total_cnt(self):
        self._total_cnt += 1


