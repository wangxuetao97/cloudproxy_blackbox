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
import traceback

BLACKBOX_CONFIG="native_config.json"
BLACKBOX_VERSION = "20201116"
BLACKBOX_INTERVAL = 20

blackbox_role = None
thread_close_event = threading.Event()
thread_close_queue = []

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
        self.closed = threading.Event()
        self.interval: timedelta = interval
        self.func = func
        self.stop_func = stop_func

    # close thread from other thread
    def close(self):
        self.stop_func()
        self.closed.set()
        self.join()
    
    # close thread from self
    def close_self(self):
        # check not already closed from outer
        if not self.closed.is_set():
            thread_close_event.set()
            thread_close_queue.append(self)

    def loop_part(self) -> bool:
        try:
            return self.func()
        except Exception as e:
            logging.warning("Exception in Job: {0}".format(e))
            os.kill(os.getpid(), signal.SIGINT) # send to main thread
    

    def run(self):
        if not self.loop_part():
            self.close_self()
            return
        while not self.closed.wait(self.interval.total_seconds()):
            logging.info("Job loop begin")
            if not self.loop_part():
                self.close_self()
                return
            logging.info("Job loop end, wait for {} seconds".format(\
                    self.interval.total_seconds()))

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
    hosts = config_json.get("ap_hostnames", [])
    if config_json.get("use_dns_ap", False):
        hosts = [nslookup('ap.agora.io')]
    use_local_cloudproxy = config_json.get("local_cloudproxy", False)
    for host in hosts:
        aip = nslookup(host)
        aport = 25000
        if aip is None:
            err_info = "Ap nslookup failed for: {}".format(host)
            logging.warning(err_info)
            print(err_info)
        if use_local_cloudproxy:
            logging.info("Use localhost cloudproxy, testing ap: {}:{}"
                    .format(aip, aport))
            addrs = [{"ip": "127.0.0.1"}]
        else:
            logging.info("Fetch proxy addr from ap: {}:{}".format(aip, aport))
            addrs = ap_fetch_cp(blackbox_role, aip, aport)
            if len(addrs) == 0:
                err_info = "Ap fetch cloudproxy edge failed."
                logging.warning(err_info)
                print(err_info)
        for cp_addr in addrs:
            eip = cp_addr.get("ip", None)
            eport = cp_addr.get("port", None)
            logging.info("Get cloudproxy addr: {}:{}".format(eip, eport))
            if blackbox_role == 'udp':
                eport = 8001 if eport == None else eport
                host_test_map[host] = TestUdp(eip, eport, aip, 8000,\
                        config_json)
            elif blackbox_role == 'tcp':
                eport = 7890 if eport == None else eport
                host_test_map[host] = TestTcp(eip, eport, aip, 25000, 8000,\
                        config_json)
            elif blackbox_role == 'tls':
                eport = 443 if eport == None else eport
                host_test_map[host] = TestTcp(eip, eport, aip, 25000, 8000,\
                        config_json, tls=True)
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
            if thread_close_event.is_set():
                for thr in thread_close_queue:
                    thr.join()
                    jobs.remove(thr)
                thread_close_event.clear()
            if len(jobs) == 0:
                logging.error("All ap address is invalid or \
no proxy address can be found, no task available.")
                sys.exit(1)
            time.sleep(1)
    except ProgramKilled:
        for job in jobs:
            job.close()
        logging.warning("program terminated")
    except Exception as e:
        for job in jobs:
            job.close()
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
    except:
        logging.warning("main exit: {0}".format(traceback.format_exc()))