import socket
import logging

class TcpClient:
    def __init__(self, ip, port, callback=None):
        self.ip = ip
        self.port = port
        self.callback = callback
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5)
        except socket.error as err:
            self._socket = None
            logging.warning("socket creation failed with error: {0}\n".format(err))

    def connect(self):
        if self._socket is None:
            return

        try:
            logging.info("connect to {0}:{1}".format(self.ip, self.port))
            self._socket.connect((self.ip, self.port))
        except Exception as e:
            self.close_socket()
            logging.warning("fail to connect {0}:{1} with err: {2}".format(self.ip, self.port, e))

    def send_data(self, data):
        if self._socket is None:
            return

        total_sent = 0
        while True:
            try:
                sent = self._socket.send(data[total_sent:])
                if sent == 0:
                    break
                total_sent += sent
            except Exception as e:
                self.close_socket()
                logging.warning("tcp send data error: {0}".format(e))
                break

    def recv_long_data(self):
        if self._socket is None:
            return b''

        chunks = []
        recv_len = 0
        while True:
            try:
                chunk = self._socket.recv(4096)
                if chunk == '':
                    break
                chunks.append(chunk)
                recv_len += len(chunk)
            except Exception as e:
                logging.warning("tcp long recv data error: {}".format(e))
                chunks = []
                break
        self.close_socket()
        return b''.join(chunks)

    def recv_short_data(self):
        if self._socket is None:
            return b''

        chunks = []
        packet = None
        bytes_recv = 0
        while True:
            try:
                chunk = self._socket.recv(4096)
                if chunk == "":
                    break
                chunks.append(chunk)
                bytes_recv += len(chunk)
                if self.callback:
                    succ, packet = self.callback(b''.join(chunks))
                    if succ:
                        break
            except Exception as e:
                logging.warning("tcp recv data error: {0}".format(e))
                chunks = []
                break
        self.close_socket()
        return packet

    def close_socket(self):
        if self._socket != None:
            self._socket.close()
            self._socket = None

    def valid_socket(self):
        return self._socket != None
