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
  pub fn new(message_type : MessageType, sequence: u32) -> Self {
    Self {
      sequence : sequence,
      message_type : message_type,
    }
  }

  pub fn ser(&self) -> Vec<u8> {
    bincode::serialize(&self).expect("Unable to serialize!!!")
  }

  pub fn des(slice: &[u8]) -> Option<Self> {
    let res = bincode::deserialize::<Self>(slice);
    match res {
      Ok(message) => Some(message),
      Err(_) => None,
    }
  }
}

// data : Vec<u8>,

/*
// Server Messages
pub struct PubKey {
  der_bytes : Vec<u8>,
}

pub struct Ack {
  sequence_aknowledgement : u32
}

pub struct RequestSend {
  sequence_requested : u32,
}

pub struct AccessGranted {
  upd_port_listening : u16,
}


// Client Messages
pub struct SimKey {
  key_bytes : Vec<u8>,
  iv_bytes : Vec<u8>
}

pub struct Auth {
  hashed_password_bytes : Vec<u8>,
  upd_port_listening : u16,
}
pub struct MovePointer {
  x : i32,
  y : i32,
}

pub struct PressKey {
  key_codes : [u8; 32],
}

pub struct RunCommand {
  current : u8,
  total : u8,
  string_bytes : Vec<u8>,
}

 */