#Secure Telemedical System


---

## Overview

This project implements a secure telemedical system that allows encrypted communication between doctors and patients using cryptographic protocols. It ensures authentication, data integrity, and confidentiality using ElGamal encryption, AES-256 encryption, and cryptographic signatures.

## Implementation Details

The system is divided into two main components:

- **Doctor (Gateway Node - GWN)**: Acts as the central server, managing authentication, key exchange, and secure message broadcasting.
- **Patient Devices**: Connect to the doctor, authenticate themselves, and receive secure messages.

The overall workflow is broken into three functional phases:

### 1. Initialization

- **Key Generation**:
  - **Doctor** and **Patient** devices each instantiate an `ElGamal` object (implemented in `utils/elgamal_utils.py`) to generate their own public-private key pairs.
  - In **Patient** (`patient.py`), the generated public key is logged and sent to the doctor as part of a key exchange request.
  - In **Doctor** (`doctor.py`), upon receiving a patient’s public key (opcode 10), the doctor updates its ElGamal parameters based on the patient’s key, ensuring both devices use compatible parameters.

### 2. Authentication & Key Exchange

- **Key Exchange**:

  - **Patient** initiates the process by sending its public key to the doctor (using opcode 10).
  - **Doctor** responds with its public key (using opcode 11).  
    This two-way exchange ensures both parties have the necessary public keys to encrypt and verify messages.

- **Authentication Request**:

  - The **Patient** sends an authentication request (opcode 10) containing:
    - A current timestamp (`ts_i`) and a random nonce (`rn_i`).
    - The doctor's ID.
    - An encrypted session key, created by encrypting the patient’s randomly generated session key with the doctor’s public key.
    - A digital signature over the message components, created using the patient’s private key.
  - The **Doctor** receives this request and performs:
    - **Timestamp Verification**: Ensuring the request is within an acceptable time window.
    - **Signature Verification**: Using the patient’s public key to verify data integrity.
    - **Session Key Extraction**: Decrypting the session key using its private key.

- **Authentication Response & Session Key Confirmation**:
  - After successful verification, the **Doctor** sends a response (opcode 20) that includes its own timestamp and nonce, along with an encrypted copy of the session key (encrypted using the patient’s public key) and a corresponding signature.
  - The **Patient** verifies the doctor's response by:
    - Checking the timestamp.
    - Verifying the doctor’s signature.
    - Decrypting and confirming the session key matches its own.
  - Finally, the **Patient** sends a session key verifier message (opcode 30) which includes a hash computed over the session key and a new timestamp. The **Doctor** validates this verifier, confirming both devices now share a common session key.

### 3. Secure Messaging

- **Group Key Establishment**:

  - Once multiple patients are authenticated, the **Doctor** aggregates the individual session keys from each verified patient.
  - A shared group key is derived (often by concatenating these keys with a random seed and hashing the result) to allow secure broadcast communication.

- **Message Broadcasting**:
  - The **Doctor** encrypts broadcast messages using AES-256 encryption (implemented in `utils/aes_utils.py`) with the group key (opcode 40).
  - Each **Patient** receives the broadcast message and decrypts it using the same group key, ensuring that only authenticated participants can read the message.

## Files Included

- `doctor.py`: Implements the doctor’s functionalities, including key exchange, authentication, session management, and secure message broadcasting.
- `patient.py`: Implements the patient’s functionalities, including key exchange, authentication, session key derivation, and message decryption.
- `utils/elgamal_utils.py`: Provides the implementation for ElGamal encryption, decryption, signing, and verification.
- `utils/aes_utils.py`: Contains AES-256 encryption and decryption functions.
- `utils/hash_utils.py`: Implements hashing functions used for signing and verifying data.
- `config.json`: Contains configuration details such as network settings and identifiers.

## Execution Steps

### 1. Setup

- Ensure you have Python 3 installed.
- Install the necessary libraries:

  ```bash
  chmod +x install.sh
  ```

  ```bash
  ./install.sh
  ```

- Verify that the `utils` directory (with `elgamal_utils.py`, `aes_utils.py`, and `hash_utils.py`) is in the project directory.

### 2. Run the Doctor Server

Start the server that will handle all incoming patient connections:

```bash
python doctor.py
```

The doctor server listens for patient connections, performs key exchange, authenticates patients, and manages secure communication.

### 3. Run Patient Instances

Launch each patient instance with a unique identifier:

```bash
python patient.py <patient_id>
```

Each patient connects to the doctor server, completes the key exchange, sends an authentication request, and waits for secure messages.

### 4. Communication Workflow

- **Key Exchange**:
  - Patients send their public keys.
  - The doctor responds with its public key.
- **Authentication**:
  - Patients send encrypted session keys and digital signatures.
  - The doctor verifies these requests, decrypts session keys, and responds with its own signed and encrypted data.
  - A session verifier is exchanged to confirm the shared session key.
- **Secure Messaging**:
  - Once authenticated, the doctor computes a shared group key.
  - The doctor broadcasts AES-encrypted messages to all authenticated patients.
  - Patients decrypt the broadcast messages using the group key.

## Performance Analysis

The performance of the cryptographic operations has been evaluated over 100 iterations. The average execution times are as follows:

| Cryptographic Operation  | Execution Time (ms) |
| ------------------------ | ------------------- |
| Key Generation (ElGamal) | 0.000410080         |
| AES Encryption           | 0.030395985         |
| Hash Computation         | 0.001857281         |
| Sign Generation(ElGamal) | 0.057859421         |

A separate performance testing script (`performance_test.py`) measures these operations by running them 100 times and calculating the average execution time. This ensures that the cryptographic primitives perform within acceptable limits for a secure telemedical system.

## Notes

- Ensure the doctor server is running before launching any patient instances.
- The system enforces strict authentication; any failed attempts will result in session termination to maintain security.
- The performance values provided are averages from local testing. Actual performance may vary based on system specifications.

This completes the setup and execution of the Secure Telemedical Conference system along with the functional implementation details.

---

This version of the README outlines each step of the implementation along with functional details directly tied to the code in `doctor.py`, `patient.py`, and the utilities. Let me know if you need further modifications or additional information!
