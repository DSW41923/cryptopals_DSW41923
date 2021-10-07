import argparse
import secrets
import requests

from challenge_02 import bytestrxor
from challenge_09 import padding_to_length
from challenge_10 import cbc_encryptor


API_URL = 'http://127.0.0.1:8000/challenges/49'
MESSAGE_TEMPLATE_V1 = "from=#{from_id}&to=#{to_id}&amount=#{amount}"
MESSAGE_TEMPLATE_V2 = "from=#{from_id}&tx_list=#{transactions}"
TRANSACTION_TEMPLATE = "{to}:{amount}"
MESSAGE_HISTORY = []
ATTACKER_ID = secrets.token_bytes(4).hex()
OTHER_IDS = []


def cbc_mac(key: bytes, pt: bytes, iv: bytes):
    pt = padding_to_length(pt, (len(pt) // 16 + 1) * 16)
    ct = cbc_encryptor(key, pt, iv)
    return ct[-16:]


def send_message_v1(from_id: str, to_id: str, amount: str):
    message = MESSAGE_TEMPLATE_V1.format(from_id=from_id, to_id=to_id, amount=amount)
    print("Sending message {}".format(message))
    iv = secrets.token_bytes(16)
    key = requests.get(API_URL + '/get_key').content
    mac = cbc_mac(key, message.encode(), iv)
    request_msg = (message.encode() + iv + mac).hex()
    if ATTACKER_ID in [from_id, to_id]:
        MESSAGE_HISTORY.append(request_msg)
    payload = {'version': 1, 'message': request_msg}
    response = requests.get(API_URL, params=payload)
    if response.status_code != 200:
        raise
    return


def send_message_v2(from_id: str, transactions: str):
    message = MESSAGE_TEMPLATE_V2.format(from_id=from_id, transactions=transactions)
    print("Sending message {}".format(message))
    key = requests.get(API_URL + '/get_key').content
    iv = (0).to_bytes(16, 'big')
    mac = cbc_mac(key, message.encode(), iv)
    request_msg = (message.encode() + mac).hex()
    MESSAGE_HISTORY.append(request_msg)
    payload = {'version': 2, 'message': request_msg}
    response = requests.get(API_URL, params=payload)
    if response.status_code != 200:
        raise
    return


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 49: CBC-MAC Message Forgery")

    # Test if server is working with version 1 protocol
    from_id = secrets.token_bytes(4).hex()  # suppose this is also the victim
    to_id = secrets.token_bytes(4).hex()
    amount = "1000 spacebucks"
    print("Testing if server is working...")
    send_message_v1(from_id, to_id, amount)
    OTHER_IDS.extend([from_id, to_id])

    desired_amount = "1000000 spacebucks"
    print("Attacker sending message with no use...")
    send_message_v1(ATTACKER_ID, ATTACKER_ID, desired_amount)
    print("Forging valid message")
    victim_message_bytes = bytes.fromhex(MESSAGE_HISTORY[-1])
    msg, iv, mac = victim_message_bytes[:-32], victim_message_bytes[-32:-16], victim_message_bytes[-16:]
    attacking_msg = MESSAGE_TEMPLATE_V1.format(from_id=from_id, to_id=ATTACKER_ID, amount=desired_amount)
    print("Desired message {}".format(attacking_msg))
    forged_iv = bytestrxor(iv, bytestrxor(msg[:16], attacking_msg.encode()[:16]))
    request_msg = (attacking_msg.encode() + forged_iv + mac).hex()
    print("Forged message {}".format(request_msg))
    payload = {'version': 1, 'message': request_msg}
    response = requests.get(API_URL, params=payload)
    if response.status_code != 200:
        print("Forged message failed!")
        return

    print("Forged message successed!")

    # Test if server is working with version 2 protocol
    transactions = TRANSACTION_TEMPLATE.format(to=to_id, amount=amount)
    print("Testing if server is working with version 2 protocol...")
    send_message_v2(from_id, transactions)
    print("Forging valid message")
    victim_message_bytes = bytes.fromhex(MESSAGE_HISTORY[-1])
    msg_bytes, mac = victim_message_bytes[:-16], victim_message_bytes[-16:]
    desired_trans = TRANSACTION_TEMPLATE.format(to=ATTACKER_ID, amount=desired_amount)

    print("Attacker sending message with no use...")
    send_message_v2(ATTACKER_ID, desired_trans)
    attacking_msg_bytes = bytes.fromhex(MESSAGE_HISTORY[-1])
    padded_msg = padding_to_length(msg_bytes, (len(msg_bytes) // 16 + 1) * 16)
    forged_msg_bytes = padded_msg + bytestrxor(mac, attacking_msg_bytes[:16]) + attacking_msg_bytes[16:]
    request_msg = forged_msg_bytes.hex()
    print("Forged message {}".format(request_msg))
    payload = {'version': 2, 'message': request_msg}
    response = requests.get(API_URL, params=payload)
    if response.status_code != 200:
        print("Forged message failed!")
        return

    print("Forged message successed!")


if __name__ == "__main__":
    main()
