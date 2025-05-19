import time
import hashlib
from utils.elgamal_utils import ElGamal, modinv

def hash_data(data):
    """Computes SHA-256 hash of input data."""
    return hashlib.sha256(data).digest()

def int_to_bytes(n, length):
    return n.to_bytes(length, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def verify_timestamp(ts_received, ts_sent, max_delay=300):
    """Checks if the received timestamp is within the allowed delay."""
    current_time = time.time()
    received_time = time.mktime(time.strptime(ts_received, "%Y-%m-%d %H:%M:%S"))
    return abs(current_time - received_time) <= max_delay
