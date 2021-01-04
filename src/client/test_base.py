from bitstring import BitStream
from datetime import datetime, timedelta
from enum import Enum
from influxdb import InfluxDBClient
from os import path,  chmod, remove
from random import randint
from re import search
from requests import get, post
from socket import gethostbyname
from typing import List

import logging
import json
import platform
import threading
import traceback

from base.voc_agent import VocAgent
from base.statistic import Statistics
from client.quality_collector import Collectors
from packet.packer import get_packet_size, get_serv_uri, unpack
from packet.packet_types import Packet, service_type_map

CLOUDPROXY_LOCAL_IP_FILE = "/data/log/agora/cloudproxy_local_ip.log"
if platform.system() == 'Windows':
    CLOUDPROXY_LOCAL_IP_FILE = "./cloudproxy_local_ip.log"
INFLUX_DEBUG = False

# check if the folder exists before use.
# return void
def append_file(data, filename):
    if not path.exists(filename):
        with open(filename, 'w') as file:
            chmod(filename, 0o666)
    with open(filename, 'a') as file:
        file.write(data)

# return client
def influxdb_client():
    if INFLUX_DEBUG: 
        client = InfluxDBClient('10.62.0.60', 8086, "", "", "cloudproxy")
    else:
        client = InfluxDBClient('report-cloudproxy.influx.agoralab.co', 443, \
                'cloudproxy_report_write', 'KPT13zfPQOBk4UMu', "cloudproxy", \
                ssl=True, verify_ssl=True)
    return client

# read my ip from local cache or fetch from server
# return None on failure, str otherwise.
def local_ip() -> str:
    if path.exists(CLOUDPROXY_LOCAL_IP_FILE):
        with open(CLOUDPROXY_LOCAL_IP_FILE, 'r') as file:
            lines = file.readlines()
            for line in lines:
                ips = search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", line)
                if ips is not None:
                    return ips.group(0)
        remove(CLOUDPROXY_LOCAL_IP_FILE)
    ip_res = get("http://ifconfig.me")
    if ip_res.status_code == 200:
        ip_str = ip_res.content.decode('utf-8')
        ips = search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", ip_str)
        if ips is not None:
            append_file(ips.group(0), CLOUDPROXY_LOCAL_IP_FILE)
            return ips.group(0)
        return None
    else:
        logging.warning("Failed in getting local ip")
        return None

def voc_join(service_path) -> Packet:
    voc_agent = VocAgent(service_path)
    if voc_agent is None:
        logging.warning("Failed in VocAgent init")
        return None
    packet = voc_agent.send_join()
    if packet is None:
        logging.warning("VocAgent response empty")
    return packet

def agolet_report(content):
    data = {
        'channel': 'Media Cloudproxy Data',
        'body': content,
        'uid': '1886000234233856',
        'token': '653d8112ab1151112a9dda5cb49031ed0dc4208b26a3bb840ddc8ef7c1bc6368'
    }
    url = "http://agolet.agoralab.co/v1/agobot/message"
    try:
        post(url, data)
    except Exception as e:
        err_info = "Failed in agolet report: {}".format(e)
        logging.warning(err_info)

def nslookup(hostname):
    ips = search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", hostname)
    if ips is not None:
        return ips.group(0)
    try:
        return gethostbyname(hostname)
    except Exception as e:
        logging.warning("Failed in Nslookup: {}".format(e))
        return None

def print_packet(packet_bytes):
    try:
        packet_size, head_size = get_packet_size(packet_bytes)
        service_id = packet_bytes[head_size] + (packet_bytes[head_size + 1] << 8)
        uri = packet_bytes[head_size + 2] + (packet_bytes[head_size + 3] << 8)
        logging.debug("packet size: {}(p)/{}(h), head size: {}, service: {}, uri: {}"\
                .format(len(packet_bytes), packet_size, head_size, service_id, uri))
        logging.debug("packet: {}".format(packet_bytes))
        packet = unpack(BitStream(packet_bytes), service_type_map[service_id][uri])
        logging.debug("{}:{}".format(packet.__class__, packet.__dict__))
    except Exception as e:
        logging.warning('Print Packet Error: {}'.format(e))

class TestAction(Enum):
    CPJOIN = 1
    CPALLOCTCP = 2
    CPALLOCUDP = 3
    CPAPTESTTCP = 4
    CPAPTESTUDP = 5
    CPRELEASETCP = 6
    CPRELEASEUDP = 7
    CPWAITRELEASE = 8
    CPPING = 9
    CPQUIT = 10
    CPCONFIGVID = 11

class TestStep:
    def __init__(self, wait = 0, action = TestAction.CPPING, **kwargs):
        self.wait = wait
        self.action = action
        for key, value in kwargs.items():
            self.__dict__[key] = value

class TestError(Enum):
    # errors in correct proxy packets
    JOIN_FAILED = 1
    ALLOC_FAILED = 2
    TCP_PAYLOAD_CORRUPTED = 3
    UDP_PAYLOAD_CORRUPTED = 4
    RELEASE_FAILED = 5
    PING_FAILED = 6
    CONFIG_CHANNEL_FAILED = 7
    # errors in unexpected proxy packets
    PACKET_CORRUPTED = 8
    WRONG_URI_RETURN = 9
    WRONG_LINKID_RETURN = 10
    CONNECT_PROXY_FAILED = 11 # includes connect failure, abruptly closing socket, invalid proxy user.
    UNEXPECTED_CHANNEL_CLOSED = 12 # TCP / UDP channel closed without expectation
    UNEXPECTED_PACKET = 13
    # errors in AP
    AP_ERROR = 14
    # error in python
    PYTHON_ERROR = 15

error_code_counts = {
    TestError.PYTHON_ERROR: 0,
    TestError.CONNECT_PROXY_FAILED: 0,
    TestError.UNEXPECTED_CHANNEL_CLOSED: 0,
    TestError.UNEXPECTED_PACKET: 0,
    TestError.PACKET_CORRUPTED: 0,
    TestError.WRONG_URI_RETURN: 0,
    TestError.WRONG_LINKID_RETURN: 0,
    TestError.JOIN_FAILED: 0,
    TestError.ALLOC_FAILED: 0,
    TestError.TCP_PAYLOAD_CORRUPTED: 0,
    TestError.UDP_PAYLOAD_CORRUPTED: 0,
    TestError.RELEASE_FAILED: 0,
    TestError.PING_FAILED: 0,
    TestError.CONFIG_CHANNEL_FAILED: 0,
    TestError.AP_ERROR: 0,
}

class TestBase:
    def __init__(self, role, hostname):
        self.role = role
        self.server_ip = hostname 
        self.stop_event = threading.Event()
        self.local_ip = local_ip()
        if self.local_ip is None:
            exit(0)
        voc_res = voc_join('/cloudproxy_blackbox_{}'.format(self.role))
        if voc_res is not None:
            self.idc = voc_res.config['idc']
        else:
            self.idc = None
        self.test_plan: List[TestStep] = []
        self.err_req_stat = Statistics() # error statistics on requests
        self.err_code_cnts = error_code_counts # error counts on errcodes. it is a global variable
        self.err_ip_cnts = {} # error counts on ips of one hostname
        self.errcheck_ts = datetime.now() # err_ip_stat last check timestamp
        self.client = influxdb_client()
    
    def stop(self):
        self.stop_event.set()

    def inc_err_ip_cnts(self):
        if self.server_ip is None:
            return
        if self.server_ip in self.err_ip_cnts:
            self.err_ip_cnts[self.server_ip] += 1
        else:
            self.err_ip_cnts[self.server_ip] = 1
    
    def inc_err_code_cnts(self, code: TestError):
        self.err_code_cnts[code] += 1

    def record_err(self, code: TestError):
        logging.warning("Record Error: {}".format(code.name))
        self.inc_err_ip_cnts()
        self.inc_err_code_cnts(code)
        self.err_req_stat.inc_err_cnt()
    
    def agolet_burst_msg(self, time_delta, remote, value) -> str:
        return "Cloudproxy blackbox role <{0}> error burst in {4} min,"\
                " error_counts: {1}, from {2} to {3}"\
                .format(self.role, value, self.local_ip, remote,\
                int(time_delta.total_seconds() / 60))

    def agolet_success_rate_msg(self, value) -> str:
        return "Cloudproxy blackbox role <{0}> success rate warning: {1} from {3} to {2}"\
                .format(self.role, value, self.server_ip, self.local_ip)

    # TODO now TCP channel only
    PING_INTERVAL = 5
    def make_plan(self):
        self.test_plan.clear()
        total_time = randint(10, 600)
        self.test_plan.append(TestStep(0, TestAction.CPJOIN))
        while total_time > 3:
            wait_time = min(randint(3, 30), total_time)
            total_time -= wait_time
            pings = int(wait_time / self.PING_INTERVAL)
            wait_time -= pings * self.PING_INTERVAL
            while pings > 0:
                pings -= 1
                self.test_plan.append(TestStep(self.PING_INTERVAL, TestAction.CPPING))
            if self.role == 'tcp' or self.role == 'tls':
                self.test_plan.append(TestStep(wait_time, TestAction.CPALLOCTCP))
                self.test_plan.append(TestStep(0, TestAction.CPAPTESTTCP))
                # AP will release connection by itself
                self.test_plan.append(TestStep(0, TestAction.CPWAITRELEASE))
            elif self.role == 'udp':
                self.test_plan.append(TestStep(wait_time, TestAction.CPAPTESTUDP))
            else:
                raise ValueError("make plan unknown role: {}".format(self.role))
        if self.role == 'udp':
            self.test_plan.append(TestStep(0, TestAction.CPQUIT))

    def print_plan(self):
        logging.info("Test plan:")
        for i, step in enumerate(self.test_plan):
            logging.info("Step #{0}: wait {1} seconds then do {2}"\
                    .format(i, step.wait, step.action.name))

    # logging and report to agolet
    def check_statistics(self):
        # check success rate
        succ = self.err_req_stat.success_rate
        if self.err_req_stat.abnormal_count > 0:
            stat_msg = "*** cloudproxy blackbox request statistics ***\n"\
                    "Role <{0}>, from: {1}, to: {2}\n"\
                    "total: {3}, err: {4}, timeout: {5}, success_rate: {6}"\
                    .format(self.role, self.local_ip, self.server_ip,\
                    self.err_req_stat.total_cnt, self.err_req_stat.err_cnt,
                    self.err_req_stat.timeout_cnt, succ)
            logging.info("Some errors have occurred.")
            logging.info(stat_msg)
            err_dict = {}
            for item, cnts in self.err_code_cnts.items():
                if cnts > 0:
                    err_dict[item.name] = cnts
            logging.warning("Error type stats: {}".format(err_dict))
        else:
            logging.info("OK, no error in this run.")
        if succ < 0.7:
            agolet_report(self.agolet_success_rate_msg(succ))
        # check ip errors every 3 minutes
        time_delta = datetime.now() - self.errcheck_ts
        if time_delta >= timedelta(minutes=3):
            for ip, cnts in self.err_ip_cnts.items():
                if cnts >= 3:
                    agolet_report(self.agolet_burst_msg(time_delta, ip, cnts))
            self.err_ip_cnts.clear()
            self.errcheck_ts = datetime.now()
        # report quality to influxdb
        self.put_influxdb()
        self.report_influxdb()

    def put_influxdb(self):
        fields = {
            "timeout_cnt": self.err_req_stat.timeout_cnt,
            "err_cnt": self.err_req_stat.err_cnt,
            "total_cnt": self.err_req_stat.total_cnt,
        }
        # move and clear
        for key, value in self.err_code_cnts.items():
            fields[key.name.lower()] = value
        Collectors.cp_collector.put(fields)
        for key in self.err_code_cnts:
            self.err_code_cnts[key] = 0

    def report_influxdb(self):
        cp_coll = Collectors.cp_collector
        if not cp_coll.ready():
            return
        try:
            json_body = [
                {
                    "measurement": "cloudproxy_quality",
                    "tags": {
                        "local_ip": self.local_ip,
                        "server_ip": self.server_ip,
                        "client_type": self.role,
                        "idc": self.idc,
                    },
                    "fields": {
                    }
                }
            ]
            json_body[0]["fields"] = {**json_body[0]["fields"], **cp_coll.move()}
            logging.info("write_point: {}".format(json_body))
            self.client.write_points(json_body)
            logging.info("point written")
        except:
            err_info = "influxdb write error: {}".format(traceback.format_exc())
            logging.warning(err_info)
        
