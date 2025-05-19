import json
import time
import os
import random
import socket
import logging 
from utils.elgamal_utils import *
from utils.hash_utils import *
from utils.aes_utils import *

log_dir = "logfiles"
os.makedirs(log_dir, exist_ok=True)

class Patient:
    def __init__(self, patient_id, doctor_id, host, port):
        self.patient_id = patient_id
        self.doctor_id = doctor_id 
        self.logger = logging.getLogger(f"patient_{self.patient_id}")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(os.path.join(log_dir, f"patient_{self.patient_id}_debug.log"))
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

        self.elgamal = ElGamal()
        self.logger.debug(f"Patient {self.patient_id} initialized with public key: {self.elgamal.public_key()}")
        self.session_key = os.urandom(16)
        self.group_key = None
        self.SK = None
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info(f"Patient {self.patient_id} connecting to doctor at {self.host}:{self.port}")
        self.sock.connect((self.host, self.port))
        self.logger.info(f"Patient {self.patient_id} connected to doctor")
        self.ts_i = None
        self.rn_i = None
        self.doctor_public_key = None

    def key_exchange(self):
        msg = {
            "opcode": 10,
            "patient_id": self.patient_id,
            "patient_public_key": list(self.elgamal.public_key())
        }
        self.sock.send(json.dumps(msg).encode())
        data = self.sock.recv(4096).decode()
        response = json.loads(data)
        if response.get("opcode") == 11:
            self.doctor_public_key = tuple(response["doctor_public_key"])
            self.logger.info(f"Received doctor's public key: {self.doctor_public_key}")
        elif response.get("opcode") == 70:
            self.logger.info(f"Error in key exchange: {response['message']}")
            self.sock.close()
            os._exit(1)
            

    def send_authentication_request(self):
        self.ts_i = time.strftime("%Y-%m-%d %H:%M:%S")
        self.rn_i = random.randint(1, 1000000)
        self.logger.debug(f"Doctor public key: {self.doctor_public_key}")
        encrypted_session_key = self.elgamal.encrypt(bytes_to_int(self.session_key), self.doctor_public_key[2])
        data_to_sign = f"{self.ts_i},{self.rn_i},{self.doctor_id},{encrypted_session_key[0]},{encrypted_session_key[1]}"
        m = int.from_bytes(hash_data(data_to_sign.encode()), 'big') % self.elgamal.p
        signature = self.elgamal.sign(m)
        request = {
            "opcode": 10,
            "patient_id": self.patient_id,
            "ts_i": self.ts_i,
            "rn_i": self.rn_i,
            "id_gwn": self.doctor_id,
            "encrypted_session_key": list(encrypted_session_key),
            "signature": list(signature),
            "public_key": list(self.elgamal.public_key())
        }
        self.sock.send(json.dumps(request).encode())
        self.logger.info(f"Patient {self.patient_id} sent authentication request to doctor")

    def handle_error(self, message):
        self.logger.info(f"Patient {self.patient_id} received error message: {message['message']}")
        self.sock.close()
    def process_doctor_response(self, response):
        self.logger.info("Doctor response received")
        ts_gwn = response["ts_gwn"]
        rn_gwn = response["rn_gwn"]
        id_d_i = response["id_d_i"]
        encrypted_session_key = tuple(response["encrypted_session_key"])
        signature = tuple(response["signature"])
        self.logger.debug(f"Processing doctor response: {response}")
        if not verify_timestamp(ts_gwn, None):
            self.logger.info("Timestamp invalid for doctor response")
            return False
        self.logger.info("Timestamp verified for doctor response")

        data_to_sign = f"{ts_gwn},{rn_gwn},{id_d_i},{encrypted_session_key[0]},{encrypted_session_key[1]}"
        m = int.from_bytes(hash_data(data_to_sign.encode()), 'big') % self.elgamal.p
        self.logger.debug(f"Data to sign value: {m}")
        self.logger.debug("Doctor public key used in verification: " + str(self.doctor_public_key[2]))
        if not self.elgamal.verify(m, *signature, self.doctor_public_key[2]):
            self.logger.info("Signature verification failed for doctor response")
            return False
        self.logger.info("Signature verified for doctor response")

        K_received = self.elgamal.decrypt(encrypted_session_key)
        K_received_bytes = int_to_bytes(K_received, 16)
        if K_received_bytes != self.session_key:
            self.logger.info(f"Session key mismatch: received {K_received_bytes.hex()}, expected {self.session_key.hex()}")
            return False
        self.logger.info(f"Session key verified for {self.patient_id}")

        data = (
            self.session_key
            + self.ts_i.encode()
            + ts_gwn.encode()
            + str(self.rn_i).encode()
            + str(rn_gwn).encode()
            + self.patient_id.encode()
            + self.doctor_id.encode()
        )
        self.SK = hash_data(data)
        self.logger.info(f"Computed shared session key SK for {self.patient_id}")
        return True

    def send_session_key_verifier(self):
        ts_i_prime = time.strftime("%Y-%m-%d %H:%M:%S")
        SKV = hash_data(self.SK + ts_i_prime.encode()).hex()
        verifier = {
            "opcode": 30,
            "ts_i_prime": ts_i_prime,
            "skv": SKV
        }
        self.sock.send(json.dumps(verifier).encode())
        self.logger.info(f"Patient {self.patient_id} sent session key verifier to doctor")

    def receive_group_key(self, message):
        decrypted = decrypt_message(message["iv"], message["ciphertext"], self.SK)
        group_key_hex = decrypted.decode()
        self.group_key = bytes.fromhex(group_key_hex)
        self.logger.info(f"Patient {self.patient_id} received and decrypted group key")

    def handle_authentication_response(self, message):
        self.logger.info(f"Patient {self.patient_id} processing doctor's authentication response")
        if self.process_doctor_response(message):
            self.send_session_key_verifier()

    def handle_group_key(self, message):
        self.logger.info(f"Patient {self.patient_id} received group key message")
        self.receive_group_key(message)

    def handle_broadcast(self, message):
        self.logger.info(f"Patient {self.patient_id} received broadcast message")
        plaintext = decrypt_message(message["iv"], message["ciphertext"], self.group_key)
        self.logger.info(f"Patient {self.patient_id} decrypted broadcast: {plaintext.decode()}")

    def handle_message(self, message):
        plaintext = decrypt_message(message["iv"], message["ciphertext"], self.SK)
        self.logger.info(f"Patient {self.patient_id} received message: {plaintext.decode()}")
        self.sock.close()

    def run(self):
        self.key_exchange()
        self.send_authentication_request()
        while True:
            try:
                data = self.sock.recv(4096).decode()
                if not data:
                    self.logger.info(f"Patient {self.patient_id} disconnected from doctor")
                    break
                message = json.loads(data)
                opcode = message.get("opcode")
                if opcode == 20:
                    self.handle_authentication_response(message)
                elif opcode == 30:
                    self.handle_group_key(message)
                elif opcode == 40:
                    self.handle_broadcast(message)
                elif opcode == 60:
                    self.handle_message(message)
                    break
                elif opcode == 70:
                    print(f"Patient {self.patient_id} received error message: {message['error']}")
                    self.handle_error(message)
                    break
            except Exception as e:
                self.logger.info(f"Error in patient {self.patient_id}: {e}")
                break
            except KeyboardInterrupt:
                self.logger.info(f"Patient {self.patient_id} shutting down")
                os._exit(0)
                
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Use: python patient.py <patient_id>")
        sys.exit(1)
    patient_id = sys.argv[1]
    config_path = "config.json"
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    doctor_id = config.get("doctor_id")
    doctor_host = config.get("ip")
    doctor_port = config.get("port")
    patient = Patient(patient_id, doctor_id, doctor_host, doctor_port)
    try:
        patient.run()
    except Exception as e:
        logging.error(f"An error occurred in patient.run(): {e}")
