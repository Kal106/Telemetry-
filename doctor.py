import json
import time
import os
import random
import socket
import threading
import logging
import sys
import signal

from utils.elgamal_utils import *
from utils.hash_utils import *
from utils.aes_utils import *
from datetime import datetime, timedelta

# Ensure logfiles directory exists.
log_dir = "logfiles"
os.makedirs(log_dir, exist_ok=True)

# Set up logging.
logger = logging.getLogger('DoctorLogger')
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(os.path.join(log_dir, 'doctor_debug.log'))
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)


def write_log(data):
    logger.debug("Logger: " + str(data))


class Doctor:
    def __init__(self, doc_id, host, port):
        self.doc_id = doc_id
        self.elgamal = ElGamal()
        self.public_key = self.elgamal.public_key()
        logger.info(f"Doctor {self.doc_id} initialized with public key: {self.public_key}")

        self.patient_keys = {}
        self.verified_patients = set()
        self.patient_pub_keys = {}
        self.patient_sockets = {}
        self.group_key = None
        self.blocked_patients = {}
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"Server active on {self.host}:{self.port} - awaiting connections.")

    def assemble_group_key(self):
        keys_list = [entry["key"] for entry in self.patient_keys.values()]
        seed_val = os.urandom(16)
        return derive_group_key(keys_list, seed_val)

    # Mini function for Key Exchange.
    def key_exchange_handler(self, connection):
        received = connection.recv(4096).decode()
        if not received:
            return
        data = json.loads(received)
        pid = data["patient_id"]
        if pid in self.verified_patients:
            logger.info(f"Key Exchange: {pid} is already authenticated. Denying service.")
            response = {"opcode": 70, "message": "Already authenticated. Connection denied."}
            connection.send(json.dumps(response).encode())
            return
        if data.get("opcode") == 10:
            pid = data["patient_id"]
            pat_pub_key = tuple(data["patient_public_key"])
            self.patient_pub_keys[pid] = pat_pub_key
            logger.debug(f"Key Exchange: Received public key for {pid}")
            # Update doctor’s ElGamal parameters based on patient public key.
            self.elgamal.p = pat_pub_key[0]
            self.elgamal.g = pat_pub_key[1]
            self.elgamal.y = pow(self.elgamal.g, self.elgamal.x, self.elgamal.p)
            self.public_key = (self.elgamal.p, self.elgamal.g, self.elgamal.y)
            logger.debug(f"Key Exchange: Updated doctor's public key: {self.public_key}")
        response = {"opcode": 11, "doctor_public_key": list(self.public_key)}
        connection.send(json.dumps(response).encode())

    # Mini function for Authentication Request.
    def authentication_request_handler(self, info, connection):
        patient_id = info["patient_id"]
        ts_i = info["ts_i"]
        rn_i = info["rn_i"]
        id_gwn = info["id_gwn"]
        enc_session = tuple(info["encrypted_session_key"])
        signature_vals = tuple(info["signature"])
        pubkey = tuple(info["public_key"])

        self.patient_pub_keys[patient_id] = pubkey
        logger.debug(f"Authentication Request: Stored public key for {patient_id}")

        if not verify_timestamp(ts_i, None):
            logger.info(f"Authentication Request: Invalid timestamp for {patient_id}")
            return False

        logger.debug(f"Authentication Request: Timestamp check passed for {patient_id}")
        to_sign = f"{ts_i},{rn_i},{id_gwn},{enc_session[0]},{enc_session[1]}"
        msg_int = int.from_bytes(hash_data(to_sign.encode()), 'big') % self.elgamal.p
        if not self.elgamal.verify(msg_int, *signature_vals, pubkey[2]):
            logger.info(f"Authentication Request: Signature check failed for {patient_id}")
            return False

        logger.debug(f"Authentication Request: Signature verified for {patient_id}")
        decrypted_val = self.elgamal.decrypt(enc_session)
        session_bytes = int_to_bytes(decrypted_val, 16)
        if len(session_bytes) != 16:
            logger.info(f"Authentication Request: Session key length error ({len(session_bytes)}) for {patient_id}")
            return False

        logger.debug(f"Authentication Request: Decrypted session key for {patient_id}: {session_bytes.hex()}")
        ts_gwn_val = time.strftime("%Y-%m-%d %H:%M:%S")
        rn_gwn_val = random.randint(1, 1000000)
        enc_return = self.elgamal.encrypt(bytes_to_int(session_bytes), pubkey[2])

        data_rsp = f"{ts_gwn_val},{rn_gwn_val},{patient_id},{enc_return[0]},{enc_return[1]}"
        msg_rsp = int.from_bytes(hash_data(data_rsp.encode()), 'big') % self.elgamal.p
        sign_rsp = self.elgamal.sign(msg_rsp)

        response = {
            "opcode": 20,
            "ts_gwn": ts_gwn_val,
            "rn_gwn": rn_gwn_val,
            "id_d_i": patient_id,
            "encrypted_session_key": list(enc_return),
            "signature": list(sign_rsp)
        }
        connection.send(json.dumps(response).encode())
        self.patient_keys[patient_id] = {
            "key": session_bytes,
            "ts_i": ts_i,
            "rn_i": rn_i,
            "ts_gwn": ts_gwn_val,
            "rn_gwn": rn_gwn_val,
            "sk": None
        }
        return True

    # Mini function for Session Verifier.
    def session_verifier_handler(self, info, patient_id):
        ts_i_prime = info["ts_i_prime"]
        session_verifier = info["skv"]

        if not verify_timestamp(ts_i_prime, None):
            logger.info(f"Session Verifier: Invalid timestamp for {patient_id}")
            return False

        logger.debug(f"Session Verifier: Timestamp valid for {patient_id}")

        data_stored = self.patient_keys[patient_id]
        k_val = data_stored["key"]
        t_i = data_stored["ts_i"]
        r_i = data_stored["rn_i"] 
        t_gwn = data_stored["ts_gwn"]
        r_gwn = data_stored["rn_gwn"]

        data_blob = (
            k_val + t_i.encode() + t_gwn.encode() +
            str(r_i).encode() + str(r_gwn).encode() +
            patient_id.encode() + self.doc_id.encode()
        )
        derived_key = hash_data(data_blob)
        computed_skv = hash_data(derived_key + ts_i_prime.encode()).hex()

        if computed_skv != session_verifier:
            logger.info(f"Session Verifier: Session key mismatch for {patient_id}")
            # self.blocked_patients[patient_id] = time.strftime("%Y-%m-%d %H:%M:%S")
            return False

        logger.debug(f"Session Verifier: Session key verified for {patient_id}")
        self.patient_keys[patient_id]["sk"] = derived_key
        return True

    def deliver_group_key(self, patient_id):
        if patient_id not in self.verified_patients:
            return
        session_key = self.patient_keys[patient_id]["sk"]
        iv_val, cipher_val = encrypt_message(self.group_key.hex(), session_key)
        data_out = {"opcode": 30, "iv": iv_val, "ciphertext": cipher_val}
        self.patient_sockets[patient_id].send(json.dumps(data_out).encode())
        logger.info(f"Group key delivered to {patient_id}")

    def broadcast_msg_to_patients(self):
        while True:
            command = input()
            if command == "broadcast" or command == "40":
                b_msg = input("Enter broadcast message: ")
                iv_data, ciph = encrypt_message(b_msg, self.group_key)
                packet = {"opcode": 40, "iv": iv_data, "ciphertext": ciph}
                for pid, skt in self.patient_sockets.items():
                    try:
                        skt.send(json.dumps(packet).encode())
                        logger.info(f"Broadcasted to {pid}: {b_msg}")
                    except Exception as e:
                        logger.error(f"Error broadcasting to {pid}: {e}")
            elif command == "disconnect":
                if self.patient_sockets:
                    for pid, skt in list(self.patient_sockets.items()):
                        if pid in self.patient_keys and self.patient_keys[pid].get("sk"):
                            disc_msg = "disconnect"
                            iv_val, ciph_val = encrypt_message(disc_msg, self.patient_keys[pid]["sk"])
                            disc_packet = {"opcode": 60, "iv": iv_val, "ciphertext": ciph_val}
                            skt.send(json.dumps(disc_packet).encode())
                        skt.close()
                        logger.info(f"Disconnected {pid}")
                        del self.patient_sockets[pid]
                        if pid in self.verified_patients:
                            self.verified_patients.discard(pid)
                    self.group_key = None
                    self.patient_sockets.clear()
                else:
                    logger.info("No active connections.")
            elif command == "":
                continue

    def handle_connection(self, connection, address):
        self.key_exchange_handler(connection)
        patient_id = None
        try:
            while True:
                dat = connection.recv(4096).decode()
                write_log(f"Data received: {dat}")
                if not dat:
                    logger.info(f"Connection closed by {address}")
                    break
                info = json.loads(dat)
                op = info.get("opcode")
                if op == 10:
                    patient_id = info["patient_id"]
                    if patient_id in self.blocked_patients:
                        blocked_time = datetime.strptime(self.blocked_patients[patient_id], "%Y-%m-%d %H:%M:%S")
                        if datetime.now() - blocked_time < timedelta(hours=24):
                            error_response = {
                                "opcode": 70,
                                "message": "Patient blocked due to previous failures. Please try again after 24 hours."
                            }
                            connection.send(json.dumps(error_response).encode())
                            logger.info(f"Blocked patient {patient_id} attempted authentication.")
                            connection.close()
                            return
                        del self.blocked_patients[patient_id]
                        logger.info(f"Unblocked patient {patient_id}")
                    logger.info(f"Authentication request from {patient_id} at {address}")
                    if self.authentication_request_handler(info, connection):
                        self.patient_sockets[patient_id] = connection
                        logger.info(f"{patient_id} authenticated.")
                    else:
                        logger.info(f"Authentication failed for {patient_id}")
                        connection.close()
                        break
                elif op == 30:
                    logger.info(f"Received session verifier from {patient_id}")
                    print(info)
                    if self.session_verifier_handler(info, patient_id):
                        self.verified_patients.add(patient_id)
                        logger.info(f"{patient_id} fully verified. Updating group key.")
                        self.group_key = self.assemble_group_key()
                        for p_id in self.verified_patients:
                            self.deliver_group_key(p_id)
                    else:
                        logger.info(f"Verification failed for {patient_id}")
                        error_packet = {"opcode": 70, "message": "Session verification failed."}
                        connection.send(json.dumps(error_packet).encode())
                        connection.close()
                        self.blocked_patients[patient_id] = time.strftime("%Y-%m-%d %H:%M:%S")
                        break
                    
        except Exception as exc:
            logger.error(f"Error with {patient_id} at {address}: {exc}")
        finally:
            if patient_id and patient_id in self.patient_sockets:
                del self.patient_sockets[patient_id]
                self.verified_patients.discard(patient_id)
                if self.verified_patients:
                    self.group_key = self.assemble_group_key()
                    for pid in self.verified_patients:
                        self.deliver_group_key(pid)
                else:
                    self.group_key = None
                logger.debug(f"Removed {patient_id} from connections.")
            connection.close()

    def run(self):
        thr = threading.Thread(target=self.broadcast_msg_to_patients)
        thr.daemon = True
        thr.start()
        logger.info("broadcast thread started.")
        while True:
            try:
                conn, addr = self.server_socket.accept()
            except KeyboardInterrupt:
                logger.info("Shutting down server due to KeyboardInterrupt")
                os._exit(0)
            logger.info(f"New connection from {addr}")
            thread_conn = threading.Thread(target=self.handle_connection, args=(conn, addr))
            thread_conn.start()


 


if __name__ == "__main__":
    config_path = "config.json"
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    doctor_id = config.get("doctor_id")
    host = config.get("ip")
    port = config.get("port")
    doc = Doctor(doctor_id, host, port)
    
    
    try:
        doc.run()
    except Exception as e:
        logger.error(f"An error occurred in doc.run(): {e}")
        sys.exit(1)