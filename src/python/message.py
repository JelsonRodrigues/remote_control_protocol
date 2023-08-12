class SimKey:
  key_bytes:bytes
  iv_bytes:bytes
  def __init__(self, key_bytes:bytes, iv_bytes:bytes):
    self.key_bytes = key_bytes
    self.iv_bytes = iv_bytes

def creteSimKeyMessage(sequence: int, key_bytes:bytes, iv_bytes:bytes) -> dict:
  return {
    'sequence' : sequence,
    'message_type' : {
      'Client' : {
        'SimKey' : {
          'key_bytes' : [int(x) for x in key_bytes],
          'iv_bytes' : [int(x) for x in iv_bytes]
        }
      }
    }
  }

# class MessageType(Enum):


# class Message:
#   sequence:int = 0
#   message_type : MessageType