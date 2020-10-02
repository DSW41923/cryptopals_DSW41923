import sys
import getopt
import secrets
import requests

from multiprocessing import Process, Manager


def get_signature_candidates(file_name, url, signature, min_response_time, new_signature_candidates):
    new_candidates = []
    manager = Manager()
    byte_candidates = manager.list()
    processes = []
    for x in range(16):
        p = Process(target=get_byte_candidates,
                    args=(file_name, url, signature, min_response_time, byte_candidates, x))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

    for b in byte_candidates:
        new_candidates.append(signature + b.to_bytes(1, 'big'))
    new_signature_candidates.extend(new_candidates)

def get_byte_candidates(file_name, url, signature, min_response_time, new_candidates, leap):

    response_time_record = []
    for y in range(leap, 256, 16):
        trial_byte = y.to_bytes(1, 'big')
        trial_signature = signature + trial_byte + bytes([0] * (19 - len(signature)))
        trial_signature = trial_signature.hex()
        trial_payload = {'file': file_name, 'signature': trial_signature}

        response = requests.get(url, params=trial_payload)
        if response.status_code == 200:
            new_candidates.extend([y])
            break
        elif response.status_code == 500 and len(signature) < 19:
            response_time = [response.elapsed.total_seconds()]
            for z in range((len(signature) // 2) * 5 + 4):
                response = requests.get(url, params=trial_payload)
                response_time.append(response.elapsed.total_seconds())
                if response.elapsed.total_seconds() < min_response_time:
                    break
            response_time_record.append(min(response_time))

    if len(signature) < 19:
        candidates = [x for x in response_time_record if x >= min_response_time]
        new_candidates.extend([(16 * response_time_record.index(m) + leap) for m in candidates])


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_31.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_31.py [-h | --help]')
            print('Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak')
            sys.exit()

    file_name = secrets.token_bytes(16).hex()
    target_url = 'http://127.0.0.1:8000/challenges/31'
    manager = Manager()

    signature_candidates = [b'']
    for x in range(20):
        min_response_time = 0.05 * (x + 1)
        new_signature_candidates = manager.list()
        processes = []
        for s in signature_candidates:
            p = Process(target=get_signature_candidates,
                        args=(file_name, target_url, s, min_response_time, new_signature_candidates))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()
        signature_candidates = new_signature_candidates

    correct_signature = None
    for s in signature_candidates:
        trial_payload = {'file': file_name, 'signature': s.hex()}
        response = requests.get(target_url, params=trial_payload)
        if response.status_code == 200:
            correct_signature = s
            break

    if correct_signature:
        print("Correct signature of file {} is {}".format(file_name, correct_signature.hex()))
    else:
        print("Unexpected error occurred while cracking signature of file " + file_name)


if __name__ == "__main__":
    main(sys.argv[1:])