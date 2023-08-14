import cbor
import socket
import hashlib
import select

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from ssl import RAND_bytes
import cryptg
import math
import random
from typing import Tuple

from message import *

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 5824         # The port used by the server
UDP_PORT_CLIENT = 63251
BUFFER_SIZE = 1 << 11 # Buffer size
AES_KEY_SIZE_IN_BITS = 256

def enc_aes(input:bytes, key:bytes, iv:bytes) -> bytes:
  message_to_encript = bytearray()
  message_to_encript.extend(input)

  needed_size = math.ceil((len(input)+8) / 16) * 16
  if len(input) < needed_size:
    size_diff = needed_size - len(input)
    message_to_encript.extend(RAND_bytes(size_diff))
  
  message_to_encript[-8:] = len(input).to_bytes(length=8, byteorder='big', signed=False)
  return cryptg.encrypt_ige(bytes(message_to_encript), key, iv)
  # return AESGCM(key).encrypt(0, input, None)

def dec_aes(input:bytes, key:bytes, iv:bytes) -> bytes:
  dec = cryptg.decrypt_ige(bytes(input), key, iv)
  size_usable = int.from_bytes(dec[-8:], 'big', signed=False)

  return dec[:size_usable]

def handle_key_exchange(
    s:socket.socket,
  ) -> Tuple[bytes, bytes, int] | None :

  data = s.recv(BUFFER_SIZE)

  # Parse message with public keys
  message = cbor.cbor.loads(data)
  
  message_receive_sequence = 0

  # Verify message is correct type
  if 'sequence' in message and 'message_type' in message:
    type = message['message_type']
    if 'Server' in type:
      server_message = type['Server']
      if 'PubKey' not in server_message:
        print("Server message is of wrong type, should have received a PubKey message")
        return None
    else:
      print("Received wrong message from server, should have received Server message instead of client message")
      return None
  else:
    print("Received wrong message from server")
    return None

  message_receive_sequence = message['sequence']
  # Read public key
  public_key_bytes = message['message_type']['Server']['PubKey']['der_bytes']
  public_key = load_der_public_key(bytes(public_key_bytes))

  # Generate AES key
  aes_key = RAND_bytes(int(AES_KEY_SIZE_IN_BITS / 8))
  iv = RAND_bytes(32) # AES_KEY_SIZE_IN_BITS / 4 

  print(f"key = {[int(x) for x in aes_key]}")
  print(f"iv = {[int(x) for x in iv]}")

  # Generate message and encode it with CBOR
  message = creteSimKeyMessage(aes_key, iv)
  encoded_cbor = cbor.cbor.dumps(message)

  # Encript with RSA public key and send

  # the overhead of PKCS1 padding is 11 bytes, so for encription and decription with
  # RSA, the size of the data to encript must be no longer than the key size in bytes - 11 bytes
  #  2048 bits key has a size of 256 bytes, while 1024 has 128 and 4096 has 512
  max_bytes = int(public_key.key_size / 8) - 11

  encripted_buffer = bytearray()

  for i in range(0, int(len(encoded_cbor) / max_bytes) + 1):
    encripted = public_key.encrypt(encoded_cbor[i * max_bytes : (i+1) * max_bytes], padding.PKCS1v15())
    encripted_buffer.extend(encripted)
  
  s.send(encripted_buffer)
  return (aes_key, iv, message_receive_sequence)

def handle_autentication(
    s:socket.socket,
    aes_key : bytes,
    iv : bytes,
    message_receive_sequence : int,
    password : str,
) -> Tuple[int, int] | bool | None: 
  # Hash password
  password_hash = hashlib.sha256(password.encode("utf-8")).digest()
  
  # Create an Auth message and encode with CBOR
  message = creteAuthMessage(password_hash, UDP_PORT_CLIENT)
  encoded_message = cbor.cbor.dumps(message)

  # Encrypt and send message
  encripted = enc_aes(encoded_message, aes_key, iv)
  s.send(encripted)

  # Receive server result, decrypt and parse to a message
  result = s.recv(BUFFER_SIZE)
  decrypted = dec_aes(result, aes_key, iv)
  message = cbor.cbor.loads(decrypted)

  # Check message is correct format
  if 'sequence' in message and 'message_type' in message:
    type = message['message_type']
    if 'Server' in type:
      server_message = type['Server']
      if 'AccessGranted' not in server_message and 'AccessDenied' not in server_message:
        print("Received wrong server message, expected either AccessGranted or AccessDenied")
        return None
    else:
      print("Got and client message instead of a server message")
      return None
  else:
    print("Received wrong message")
    return None
  
  message_receive_sequence = message['sequence']
  if 'AccessGranted' in message['message_type']['Server']:
    print("Granted")
    udp_port_server =  message['message_type']['Server']['AccessGranted']['upd_port_listening']
    return (udp_port_server, message_receive_sequence)
  if 'AccessDenied' in message['message_type']['Server']:
    print("Denied")
    return False
  
  return None

def handle_send_message(
    aes_key:bytes,
    iv:bytes,
    udp_port_server:int,
    message_receive_sequence:int
  ):
  messages_list = []
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(('LOCALHOST', UDP_PORT_CLIENT))
    server_address = (HOST, udp_port_server)

    while True:
      #  Check if got any message from server
      readable, writable, exceptional = select.select([s], [], [], 0)
      if s in readable:
        message_got = s.recv(BUFFER_SIZE)
        message_dec = dec_aes(message_got, aes_key, iv)
        message = cbor.cbor.loads(message_dec)

        # check message type
        if 'sequence' in message and 'message_type' in message:
          type = message['message_type']
          if 'Server' in type:
            server_message = type['Server']
            
            if 'Ack' in server_message:
              print("Got Ack")
              ack_number = message['message_type']['Server']['Ack']['sequence_aknowledgement']
              for message in messages_list:
                sequence = message['sequence']
                if sequence <= ack_number:
                  messages_list.remove(message)
            elif 'RequestSend' in server_message:
              print("Got request send")
              requested_number = message['message_type']['Server']['RequestSend']['sequence_requested']
              for index in range(len(messages_list)):
                message = messages_list[index]
                sequence = message['sequence']
                if sequence >= requested_number:
                  encoded_message = cbor.cbor.dumps(message)
                  encrypted = enc_aes(encoded_message, aes_key, iv)
                  s.sendto(encrypted, server_address)
          else:
            print("Got and client message instead of a server message")
        else:
          print("Received wrong message")


      v = int(input("Digite uma ação, 1 mover mouse aleatoriamente, 2 pressionar espaco, 3 quit: "))
      if v == 1:
        message = creteMovePointerMessage(random.randint(-50, 50), random.randint(-50, 50))
      elif v == 2:
        keys = [0 for _ in range(32)] 
        keys[0] = 0x20
        message = cretePressKeyMessage(keys)
      elif v == 3:
        message = creteQuitMessage()
        messages_list.append(message)
        encoded_message = cbor.cbor.dumps(message)
        encrypted = enc_aes(encoded_message, aes_key, iv)
        s.sendto(encrypted, server_address)
        return
      else:
        continue
      
      messages_list.append(message)
      encoded_message = cbor.cbor.dumps(message)
      encrypted = enc_aes(encoded_message, aes_key, iv)
      s.sendto(encrypted, server_address)

def main():
  # Try open TCP connection
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Handle key exchange
    result = handle_key_exchange(s)
    if result is None:
      print("Error exchanging keys with server")
      return
    
    (aes_key, iv, receiving_sequence) = result

    password = "PasswordExample"

    result = handle_autentication(s, aes_key, iv, receiving_sequence, password)
    
    if result is None:
      print("Error autenticating")
      return
    if result is False:
      print("Access denied")
      return
    
    (udp_port_server, receiving_sequence) = result
  
  handle_send_message(aes_key, iv, udp_port_server, receiving_sequence)

# Call Main
main()