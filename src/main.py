from datetime import timedelta

from client.test_tcp import TestTcp
from client.test_udp import TestUdp
from client.ap_fetch_settings import ap_fetch_cp
from client.test_base import nslookup
from client.quality_collector import Collectors

import json
import logging
import os
import platform
import signal
import sys
import threading
import time

BLACKBOX_CONFIG="native_config.json"
BLACKBOX_VERSION = "20201116"
BLACKBOX_INTERVAL = 60

blackbox_role = None

def load_config():
    j = None
    try:
        with open(BLACKBOX_CONFIG, "r") as f:
            j = json.load(f)
    except Exception as e:
        print("load config file fail: {}".format(e))
    return j

def load_argv():
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == '-v'):
        print("version {}".format(BLACKBOX_VERSION))
        sys.exit(0)
    elif len(sys.argv) == 3 and sys.argv[1] == '-r':
        global blackbox_role
        blackbox_role = sys.argv[2]
    else:
        print("invalid args.")
        sys.exit(1)

class Job(threading.Thread):
    def __init__(self, interval, func, stop_func):
        threading.Thread.__init__(self)
        self.daemon = False
        self.stopped = threading.Event()
        self.interval: timedelta = interval
        self.func = func
        self.stop_func = stop_func

    def stop(self):
        self.stopped.set()
        self.stop_func()
        self.join()
    
    def loop_part(self):
        try:
            self.func()
        except Exception as e:
            logging.warning("Exception in Job: {0}".format(e))
            os.kill(os.getpid(), signal.SIGINT) # send to main thread

    def run(self):
        self.loop_part()
        while not self.stopped.wait(self.interval.total_seconds()):
            self.loop_part()

class ProgramKilled(Exception):
    pass

def signal_handler(signum, frame):
    raise ProgramKilled

def main():
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    host_test_map = {}
    config_json = load_config()
    if config_json is None:
        logging.warning("Load config failed. Exit now.")
        sys.exit(1)
    hosts = config_json["ap_hostnames"]
    for host in hosts:
        aip = nslookup(host)
        if aip is None:
            err_info = "Ap nslookup failed for: {}".format(host)
            logging.warning(err_info)
            print(err_info)
            sys.exit(1)
        eip, eport = ap_fetch_cp(blackbox_role, aip, 9700)
        if eip is None or eport is None:
            err_info = "Ap fetch cloudproxy edge failed."
            logging.warning(err_info)
            print(err_info)
            sys.exit(1)
        if blackbox_role == 'udp':
            host_test_map[host] = TestUdp(eip, eport, aip, 8000)
        elif blackbox_role == 'tcp':
            host_test_map[host] = TestTcp(eip, eport, aip, 9700, 8000)
        elif blackbox_role == 'tls':
            host_test_map[host] = TestTcp(eip, eport, aip, 9700, 8000, tls=True)
        else:
            raise ValueError("main: unknown role: {}".format(blackbox_role))

    jobs = []
    for _, test in host_test_map.items():
        job = Job(interval=timedelta(seconds=BLACKBOX_INTERVAL), func=test.run, stop_func=test.stop)
        job.start()
        jobs.append(job)
    Collectors.cp_collector.set_count(len(jobs))
    try:
        while True:
            time.sleep(1)
    except ProgramKilled:
        for job in jobs:
            job.stop()
        logging.warning("program terminated")
    except Exception as e:
        for job in jobs:
            job.stop()
        logging.warning("Unexpected Error: {0}".format(e))


if __name__ == '__main__':
    load_argv()
    if platform.system() == 'Windows':
        blackbox_log_file = "./cloudproxy_blackbox_{}.log".format(blackbox_role)
    else:
        blackbox_log_file = "/data/log/agora/cloudproxy_blackbox_{}.log".format(blackbox_role)
    logging.basicConfig(format='[%(levelname)s %(asctime)s,'\
                        '%(funcName)s:%(lineno)d] %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=blackbox_log_file,
                        level=logging.INFO)
    try:
        main()
    except Exception as e:
        logging.warning("main exit: {0}".format(e))