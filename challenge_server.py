import sys
import socketserver
import http.server
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs

from challenge_02 import bytestrxor
from challenge_31 import insecure_compare


KEY = secrets.token_bytes(16)

class HMACbySHA1(object):
    """docstring for HMAC_SHA1"""
    def __init__(self):
        super(HMACbySHA1, self).__init__()
        self.blockSize = 512

    def hmac_text(self, key, message):
        if type(message) != bytes:
            message = message.encode()

        if len(key) > self.blockSize:
            key = self.mac_text(key)

        if len(key) < self.blockSize:
            key += b'0' * (self.blockSize - len(key))

        o_key_pad = bytestrxor(key, bytes([0x5c] * self.blockSize))
        i_key_pad = bytestrxor(key, bytes([0x36] * self.blockSize))

        return self.mac_text(o_key_pad + self.mac_text(i_key_pad + message))

    @staticmethod
    def mac_text(text):
        backend = default_backend()
        digest = Hash(SHA1(), backend=backend)
        digest.update(text)

        return digest.finalize()

class CryptopalRequestHandler(http.server.BaseHTTPRequestHandler):
    # noinspection PyPep8Naming
    def do_GET(self):
        parsed_request_url = urlparse(self.path)
        request_path = parsed_request_url.path.split('/')
        assert request_path[1] == 'challenges'

        if request_path[-1] in ['31', '32'] :

            if request_path[-1] == '31':
                delay = 0.050
            elif request_path[-1] == '32':
                delay = 0.005
            else:
                delay = 1

            request_query = parse_qs(parsed_request_url.query)
            file = request_query.get('file')[0]
            signature = request_query.get('signature')[0]
            signature = bytes.fromhex(signature)

            hmac_generator = HMACbySHA1()
            hmac = hmac_generator.hmac_text(KEY, file)

            if len(signature) != len(hmac):
                self.send_error(500)
                return

            if insecure_compare(delay, signature, hmac):
                self.send_response(200)
                self.end_headers()
                return
            else:
                self.send_error(500)
                return


def run_server(argv):

    if argv[1:]:
        port = int(argv[1])
    else:
        port = 8000
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", port), CryptopalRequestHandler)
    print("serving at port", port)
    httpd.serve_forever()

if __name__ == "__main__":
    run_server(sys.argv[1:])
