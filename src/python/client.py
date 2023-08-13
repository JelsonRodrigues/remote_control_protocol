import cbor
import socket
import hashlib

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from ssl import RAND_bytes
import cryptg
import math

from message import *

def enc_aes(input:bytes, key:bytes, iv:bytes) -> bytes:
    message_to_encript = bytearray()
    message_to_encript.extend(input)

    needed_size = math.ceil((len(input)+8) / 16) * 16
    if len(input) < needed_size:
        size_diff = needed_size - len(input)
        message_to_encript.extend(RAND_bytes(size_diff))
    
    message_to_encript[-8:] = len(input).to_bytes(length=8, byteorder='big', signed=False)
    return cryptg.encrypt_ige(bytes(message_to_encript), key, iv)

def dec_aes(input:bytes, key:bytes, iv:bytes) -> bytes:
    dec = cryptg.decrypt_ige(bytes(input), key, iv)
    size_usable = int.from_bytes(dec[-8:], 'big', signed=False)

    return dec[:size_usable]

def handle_key_exchange():
    return

def handle_autentication():
    return

def handle_send_message():
    return

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 5824         # The port used by the server

client_state = ClientStates.StartingConnection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(2048)

    client_state = ClientStates.ExchangingKeys
    message = cbor.cbor.loads(data)

    sequence_received = message['sequence']
    # Read public key
    public_key_bytes = message['message_type']['Server']['PubKey']['der_bytes']
    public_key = load_der_public_key(bytes(public_key_bytes))

    # Generate AES key
    AES_KEY_SIZE_IN_BITS = 256

    aes_key = RAND_bytes(int(AES_KEY_SIZE_IN_BITS / 8))
    iv = RAND_bytes(32) # AES_KEY_SIZE_IN_BITS / 4 
    m = creteSimKeyMessage(aes_key, iv)

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

    client_state = ClientStates.ExchangingKeys

    password = "PasswordExample"
    password_hash = hashlib.sha256(password.encode("utf-8")).digest()

    udp_port = 63251
    message = creteAuthMessage(password_hash, udp_port)
    encoded_message = cbor.cbor.dumps(message)

    encripted = enc_aes(encoded_message, aes_key, iv)
    s.send(encripted)

    result = s.recv(2048)

    decrypted = dec_aes(result, aes_key, iv)

    message = cbor.cbor.loads(decrypted)

    if 'AccessGranted' in message['message_type']['Server']:
        print("Granted")
        client_state = ClientStates.SendingMessage
    if 'AccessDenied' in message['message_type']['Server']:
        print("Denied")
        client_state = ClientStates.StartingConnection
