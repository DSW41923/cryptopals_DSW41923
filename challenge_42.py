import argparse
import asn1
import re

from cryptography.hazmat.primitives.hashes import Hash, MD5
from cryptography.hazmat.backends import default_backend
from typing import Union

from challenge_39 import simple_rsa_keygen, generate_big_primes, simple_rsa_decrypt, simple_rsa_encrypt
from challenge_40 import cubic_root_bignum


def simple_md5(text: bytes) -> bytes:
    backend = default_backend()
    digest = Hash(MD5(), backend=backend)
    digest.update(text)
    return digest.finalize()


def simple_asn1_encode(msg: Union[bytes, str]) -> bytes:
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(msg)
    return encoder.output()


def simple_asn1_decode(encoded_msg: Union[bytes, str]) -> bytes:
    decoder = asn1.Decoder()
    decoder.start(encoded_msg)
    tag, value = decoder.read()
    return value


def simple_padding(formatted_message: bytes, block_length: int, padding="PKCS1.5") -> bytes:
    if padding == "PKCS1.5":
        # encoded_payload = ASN.1 format prepended hash_function_name.encode() + hashed_message
        padding_length = block_length - 3 - len(formatted_message)
        padded_payload = bytes.fromhex("0001") + bytes([255] * padding_length) + bytes.fromhex("00") + formatted_message
        print(padded_payload.hex())
        return padded_payload
    else:
        raise NotImplementedError


def verify_padding(message, payload, padding="PKCS1.5"):
    if padding == "PKCS1.5":
        if re.match(b'\x00\x01(\xff)+\x00', payload):
            # encoded_payload = ASN.1 encode of hash_function_name.encode() + hashed_message
            encoded_payload = re.sub(b'\x00\x01(\xff)+\x00', b'', payload)
            decoded_payload = simple_asn1_decode(encoded_payload)
            if decoded_payload.startswith(b"MD5"):
                hashed_message = decoded_payload.replace(b"MD5", b'')[:32]
                return hashed_message == simple_md5(message.encode())
        return False
    else:
        raise NotImplementedError


def simple_rsa_sign(key, message, block_length, padding="PKCS1.5"):
    hashed_message = simple_md5(message.encode())
    hash_function_name = b"MD5"
    asn1_formatted_message = simple_asn1_encode(hash_function_name + hashed_message)
    padded_payload = simple_padding(asn1_formatted_message, block_length, padding=padding)
    msg_num = int.from_bytes(padded_payload, 'big')
    signature_num = simple_rsa_encrypt(key, msg_num)
    return signature_num.to_bytes(block_length, 'big')


def simple_rsa_verify(key, message, signature, block_length, padding="PKCS1.5"):
    signature_num = int.from_bytes(signature, 'big')
    msg_num = simple_rsa_decrypt(key, signature_num)
    padded_payload = msg_num.to_bytes(block_length, 'big')
    return verify_padding(message, padded_payload, padding)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 42: Bleichenbacher's e=3 RSA Attack")

    p, q = generate_big_primes(e=3, length=1024)
    pk, sk = simple_rsa_keygen(p, q, e=3)
    trial_text = "hi mom"
    block_length = 1024 // 8
    print("Generating RSA signature of message \"{}\"".format(trial_text))
    signature = simple_rsa_sign(sk, trial_text, block_length)
    print("Generated signature (in hex) as {}".format(signature.hex()))
    print("Verifying signature...")
    print("Is signatue valid? {}".format(simple_rsa_verify(pk, trial_text, signature, block_length)))

    print("Forging RSA signature of message \"{}\"".format(trial_text))
    hashed_message = simple_md5(trial_text.encode())
    hash_function_name = b"MD5"
    ff_num = 1
    while True:
        forged_signature_base = bytes.fromhex("0001") + bytes.fromhex("ff") * ff_num + bytes.fromhex("00")\
                                + simple_asn1_encode(hash_function_name + hashed_message)

    # May not be a perfect cube here!
        garbage_length = (block_length - len(forged_signature_base)) * 8
        signature_num_base = int.from_bytes(forged_signature_base, 'big') << garbage_length
        trial_cubic_root = cubic_root_bignum(signature_num_base)
        if (trial_cubic_root + 1) ** 3 - trial_cubic_root ** 3 < 2 ** garbage_length:
            forged_signature_num = trial_cubic_root + 1
            break
        ff_num += 1

    forged_signatue = forged_signature_num.to_bytes(block_length, 'big')
    print("Forged signature in hex as {}".format(forged_signatue.hex()))
    print("Verifying signature...")

    print("Is forged signatue valid? {}".format(simple_rsa_verify(pk, trial_text, forged_signatue, block_length)))


if __name__ == "__main__":
    main()
