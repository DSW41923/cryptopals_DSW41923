import sys
import socketserver
import http.server
import secrets
import re

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs

from challenge_02 import bytestrxor
from challenge_31 import insecure_compare
from challenge_49 import cbc_mac

KEY = secrets.token_bytes(16)


# noinspection PyPep8Naming
class HMAC(object):
    """General HMAC for any hash function"""

    def __init__(self, blockSize, mac_func):
        super(HMAC, self).__init__()
        self.blockSize = blockSize
        self.mac_func = mac_func

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

    def mac_text(self, text):
        backend = default_backend()
        digest = Hash(self.mac_func(), backend=backend)
        digest.update(text)
        return digest.finalize()


class CryptopalRequestHandler(http.server.BaseHTTPRequestHandler):
    # noinspection PyPep8Naming
    def do_GET(self):
        parsed_request_url = urlparse(self.path)
        request_path = parsed_request_url.path.split('/')
        assert request_path[1] == 'challenges'

        if request_path[-1] in ['31', '32']:

            if request_path[-1] == '31':
                delay = 0.050
            elif request_path[-1] == '32':
                delay = 0.005
            else:
                delay = 1

            request_query_bytes = parse_qs(parsed_request_url.query)
            file = request_query_bytes.get('file')[0]
            signature = request_query_bytes.get('signature')[0]
            signature = bytes.fromhex(signature)

            hmac_generator = HMAC(blockSize=512, mac_func=SHA1)
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

        elif request_path[-1] == '49':
            request_query = parse_qs(parsed_request_url.query)
            version = request_query.get('version')[0]
            request_message_bytes = bytes.fromhex(request_query.get('message')[0])
            if version == '1':
                message, iv = request_message_bytes[:-32], request_message_bytes[-32:-16]
            elif version == '2':
                message = request_message_bytes[:-16]
                iv = (0).to_bytes(16, 'big')
            else:
                self.send_error(501)
                return

            if cbc_mac(KEY, message, iv) == request_message_bytes[-16:]:
                if version == '1':
                    for from_id, to_id, amount in re.findall(r'from=#(\w+)&to=#(\w+)&amount=#([\w ]+)', message.decode()):
                        print("Doing transaction: Trasfering {} from account {} to account {}."
                              .format(amount, from_id, to_id))
                elif version == '2':
                    from_id = re.search(rb'from=#(\w+)&', message).group(1).decode()
                    tx_list = re.search(rb'tx_list=#(.+)', message).group(1)
                    for to_id, amount in re.findall(rb'(\w+):([\w ]+)', tx_list):
                        print("Doing transaction: Trasfering {} from account {} to account {}."
                              .format(amount.decode(), from_id, to_id.decode()))
                else:
                    self.send_error(501)
                    return

                self.send_response(200)
                self.end_headers()
                return
            else:
                self.send_error(500)
                return

        elif request_path[-1] == 'get_key':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(KEY)
            return

        else:
            self.send_error(501)
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
