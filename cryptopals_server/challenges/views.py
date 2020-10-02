from django.http import HttpResponse

import secrets
import time

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend


KEY = secrets.token_bytes(16)

# Create your views here.

def bytestrxor(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])

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


def insecure_compare(request):
    file = request.GET.get('file')
    signature = request.GET.get('signature')
    signature = bytes.fromhex(signature)

    hmac_generator = HMACbySHA1()
    hmac = hmac_generator.hmac_text(KEY, file)

    for b1, b2 in zip(signature, hmac):
        if b1 != b2:
            return HttpResponse(status=500)
        else:
            time.sleep(0.050)

    return HttpResponse(status=200)
