import cbor
import socket

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from ssl import RAND_bytes

from message import *

# import tgcrypto
# tgcrypto.ige256_encrypt()

# import cryptg

# cryptg.encrypt_ige()

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 5824         # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(2048)

    message = cbor.cbor.loads(data)

    sequence_send = 0
    sequence_received = message['sequence']

    # Read public key
    public_key_bytes = message['message_type']['Server']['PubKey']['der_bytes']
    public_key = load_der_public_key(bytes(public_key_bytes))

    # Generate AES key
    AES_KEY_SIZE_IN_BITS = 256

    aes_key = RAND_bytes(int(AES_KEY_SIZE_IN_BITS / 8))
    iv = RAND_bytes(int(AES_KEY_SIZE_IN_BITS / 4))
    m = creteSimKeyMessage(sequence_send, aes_key, iv)
    sequence_send += 1
    
    print(f"key = {[int(x) for x in aes_key]}")
    print(f"iv = {[int(x) for x in iv]}")

    encoded_cbor = cbor.cbor.dumps(m)

    # the overhead of PKCS1 padding is 11 bytes, so for encription and decription with
    # RSA, the size of the data to encript must be no longer than the key size in bytes - 11 bytes
    #  2048 bits key has a size of 256 bytes, while 1024 has 128 and 4096 has 512
    max_bytes = int(public_key.key_size / 8) - 11

    encripted_buffer = bytearray()

    for i in range(0, int(len(encoded_cbor) / max_bytes) + 1):
        encripted = public_key.encrypt(encoded_cbor[i * max_bytes : (i+1) * max_bytes], padding.PKCS1v15())
        encripted_buffer.extend(encripted)
        
    s.send(encripted_buffer)
    