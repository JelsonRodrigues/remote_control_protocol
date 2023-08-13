from enum import Enum
class ClientStates(Enum):
  StartingConnection = 0,
  ExchangingKeys = 1,
  Authenticating = 2,
  SendingMessage = 3,

message_sequence = 0

def creteSimKeyMessage(key_bytes:bytes, iv_bytes:bytes) -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : {
        'SimKey' : {
          'key_bytes' : [int(x) for x in key_bytes],
          'iv_bytes' : [int(x) for x in iv_bytes]
        }
      }
    }
  }

def creteAuthMessage(hashed_password_bytes:bytes, upd_port_listening:int) -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : {
        'Auth' : {
          'hashed_password_bytes' : [int(x) for x in hashed_password_bytes],
          'upd_port_listening' : upd_port_listening
        }
      }
    }
  }

def creteMovePointerMessage(x:int, y:int) -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : {
        'MovePointer' : {
          'x' : x,
          'y' : y
        }
      }
    }
  }

def cretePressKeyMessage(key_codes : [int]) -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : {
        'PressKey' : {
          'key_codes' : key_codes[0:32]
        }
      }
    }
  }

def creteRunCommandMessage(current : int, total : int, string_bytes : bytes ) -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : {
        'RunCommand' : {
          'current' : current,
          'total' : total,
          'string_bytes' : [int(x) for x in string_bytes]
        }
      }
    }
  }

def creteQuitMessage() -> dict:
  global message_sequence
  message_sequence += 1
  return {
    'sequence' : message_sequence,
    'message_type' : {
      'Client' : 'Quit',
    }
  }