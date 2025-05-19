import time
from utils.elgamal_utils import ElGamal
from utils.hash_utils import hash_data
from utils.aes_utils import encrypt_message

# Initialize ElGamal encryption
gelgamal = ElGamal()

# Define number of iterations
num_iterations = 100

# Lists to store execution times
keygen_times = []
sign_times = []
aes_enc_times = []
hash_times = []

for _ in range(num_iterations):
    # Measure key generation time
    start_time = time.time()
    private_key, public_key = gelgamal.x, gelgamal.public_key()
    keygen_times.append((time.time() - start_time) * 1000)

    # Measure ElGamal signature time
    message = b"Test message for signing"
    hashed_msg = int.from_bytes(hash_data(message), 'big') % gelgamal.p
    start_time = time.time()
    signature = gelgamal.sign(hashed_msg)
    sign_times.append((time.time() - start_time) * 1000)

    # Measure AES encryption time
    aes_key = b"ThisIsASecretKey"
    start_time = time.time()
    iv, ciphertext = encrypt_message("Sensitive Data", aes_key)
    aes_enc_times.append((time.time() - start_time) * 1000)

    # Measure hash computation time
    start_time = time.time()
    hashed_value = hash_data(b"Sample data to hash")
    hash_times.append((time.time() - start_time) * 1000)

# Calculate average execution times
avg_keygen_time = sum(keygen_times) / num_iterations
avg_sign_time = sum(sign_times) / num_iterations
avg_aes_enc_time = sum(aes_enc_times) / num_iterations
avg_hash_time = sum(hash_times) / num_iterations

# Display final results
print("\n===== Performance Analysis Results (Averaged over 100 runs) =====")
print(f"Key Generation (ElGamal): {avg_keygen_time:.9f} ms")
print(f"AES Encryption: {avg_aes_enc_time:.9f} ms")
print(f"Hash Computation: {avg_hash_time:.9f} ms")
print(f"Signature Generation (ElGamal): {avg_sign_time:.9f} ms")


