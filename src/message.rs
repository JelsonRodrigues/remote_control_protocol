use serde::{Serialize, Deserialize};

pub enum ServerStates {
  WaitingForConnection,
  ExchangingKeys,
  AuthenticatingClient,
  WaitingForMessages,
}

pub enum ClientStates {
  StartingConnection,
  ExchangingKeys,
  Authenticating,
  SendingMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessages {
  SimKey { key_bytes : Vec<u8>, iv_bytes : Vec<u8> },
  Auth { hashed_password_bytes : Vec<u8>, upd_port_listening : u16 },
  MovePointer { x : i32, y : i32 },
  PressKey { key_codes : [u8; 32]},
  RunCommand { current : u8, total : u8, string_bytes : Vec<u8> },
  Quit,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMessages {
  PubKey { der_bytes : Vec<u8> },
  AccessGranted { upd_port_listening : u16 },
  AccessDenied,
  Ack { sequence_aknowledgement : u32 },
  RequestSend { sequence_requested : u32 },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
  Client(ClientMessages),
  Server(ServerMessages)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
  pub sequence : u32,
  pub message_type : MessageType,
}

impl Message {
  pub fn new(sequence: u32, message_type : MessageType) -> Self {
    Self {
      sequence : sequence,
      message_type : message_type,
    }
  }

  pub fn ser(&self) -> Vec<u8> {
    serde_cbor::to_vec(&self).unwrap()
  }

  pub fn des(slice: &[u8]) -> Option<Self> {
    let res = serde_cbor::from_slice(slice);
    match res {
      Ok(message) => Some(message),
      Err(err) =>{
        println!("Eror {:?}", err);
        None 
      },
    }
  }
}