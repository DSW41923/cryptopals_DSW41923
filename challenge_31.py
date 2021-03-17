import sys
import getopt
import secrets
import requests
import time


def insecure_compare(delay, file_signature, hmac):

    for b1, b2 in zip(file_signature, hmac):
        if b1 != b2:
            return False
        else:
            time.sleep(delay)

    return True

def get_correct_signature(url, file_name, timing_difference):

    signature_candidates = [b'']
    min_response_time = 0

    while any([len(s) != 20 for s in signature_candidates]):
        ideal_response_time = min_response_time + timing_difference
        response_time_record = []
        new_signature_candidates = []
        for s in signature_candidates:
            byte_candidates, response_time = get_byte_candidates(
                url, file_name, s, ideal_response_time, min_response_time)
            if byte_candidates:
                new_signature_candidates.extend([(s + b.to_bytes(1, 'big')) for b in byte_candidates])
                response_time_record.append(response_time)
                if response_time == 1:
                    break
        if new_signature_candidates and response_time_record:
            min_response_time = (min(response_time_record) // timing_difference) * timing_difference
            signature_candidates = new_signature_candidates
        else:
            min_response_time -= timing_difference

    for s in signature_candidates:
        trial_payload = {'file': file_name, 'signature': s.hex()}
        response = requests.get(url, params=trial_payload)
        if response.status_code == 200:
            return s

def get_byte_candidates(url, file_name, signature, ideal_response_time, min_response_time):

    byte_candidates = []
    byte_trial_results = []
    for x in range(256):
        trial_signature = signature + x.to_bytes(1, 'big') + bytes([0] * (19 - len(signature)))
        trial_payload = {'file': file_name, 'signature': trial_signature.hex()}
        trial_result = try_byte_candidate(url, trial_payload, ideal_response_time, len(signature))
        if trial_result == 1:
            return[x], 1
        elif trial_result < min_response_time:
            return [], 0
        elif trial_result >= ideal_response_time and len(signature) < 19:
            byte_candidates.append(x)
            byte_trial_results.append(trial_result)
        else:
            continue

    if len(byte_candidates) > 0:
        print("Found {} byte candidates for the next byte of current signature {}".format(
            len(byte_candidates), signature.hex()))

    return byte_candidates, min(byte_trial_results) if byte_trial_results else 0

def try_byte_candidate(url, payload, ideal_response_time, correct_signature_length):

    response_time_record = []
    for z in range(10):
        try:
            response = requests.get(url, params=payload)
            response_time = response.elapsed.total_seconds()
            response_time_record.append(response_time)

            if response.status_code == 200:
                return 1
            elif response.status_code == 500:
                if correct_signature_length == 19 or response_time < ideal_response_time:
                    break
        except requests.exceptions.ConnectionError:
            time.sleep(0.5)

    return min(response_time_record)


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

    target_url = 'http://127.0.0.1:8000/challenges/31'
    file_name = secrets.token_bytes(16).hex()
    timing_difference = 0.050
    correct_signature = get_correct_signature(target_url, file_name, timing_difference)

    if correct_signature:
        print("Correct signature of file {} is {}".format(file_name, correct_signature.hex()))
    else:
        print("Unexpected error occurred while cracking signature of file " + file_name)


if __name__ == "__main__":
    main(sys.argv[1:])