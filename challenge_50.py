import argparse


from challenge_02 import bytestrxor
from challenge_09 import padding_to_length
from challenge_49 import cbc_mac


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 50: Hashing with CBC-MAC")
    js_snippet = b"alert('MZA who was that?');\n"
    key = b'YELLOW SUBMARINE'
    iv = bytes([00]) * 16
    hash_result = "296b8d7cb78a243dda4d0a61d33bbdd1"
    assert cbc_mac(key, js_snippet, iv).hex() == hash_result
    print("Original snippet is {}".format(js_snippet))
    desired_js_snippet = b"alert('Ayo, the Wu is back!');\n"
    padded_msg = padding_to_length(desired_js_snippet, (len(desired_js_snippet) // 16 + 1) * 16)
    padded_msg_hash_result = cbc_mac(key, desired_js_snippet, iv).hex()
    forged_msg_bytes = padded_msg + bytestrxor(bytes.fromhex(padded_msg_hash_result), js_snippet[:16]) + js_snippet[16:]
    print("Forged snippet is {}".format(forged_msg_bytes))
    if cbc_mac(key, forged_msg_bytes, iv).hex() != hash_result:
        print("Forged snippet failed!")
        return

    print("Forged snippet successed!")


if __name__ == "__main__":
    main()
