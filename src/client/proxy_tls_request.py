from client.proxy_tcp_request import ProxyTcpRequest

import ssl
import logging
import traceback

class ProxyTlsRequest(ProxyTcpRequest):
    def connect(self, ip, port):
        super().connect(ip, port)
        if self._socket is None:
            return
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
            ssock = context.wrap_socket(self._socket, server_hostname="*.agora.io")
            logging.info(ssock.version())
        except Exception:
            logging.warning("ssl handshake error: {}".format(traceback.format_exc()))
            self.close()
            return
        self._socket = ssock

