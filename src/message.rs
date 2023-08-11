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

pub enum ClientMessages {
  SimKey { key_bytes : Vec<u8>, iv_bytes : Vec<u8> },
  Auth { hashed_password_bytes : Vec<u8>, upd_port_listening : u16 },
  MovePointer { x : i32, y : i32 },
  PressKey { key_codes : [u8; 32]},
  RunCommand { current : u8, total : u8, string_bytes : Vec<u8> },
}

pub enum ServerMessages {
  PubKey { der_bytes : Vec<u8> },
  AccessGranted { upd_port_listening : u16 },
  AccessDenied,
  Ack { sequence_aknowledgement : u32 },
  RequestSend { sequence_requested : u32 },
}

pub enum MessageType {
  Client(ClientMessages),
  Server(ServerMessages)
}

pub struct Message {
  lengh : u16,
  sequence : u32,
  message_type : MessageType,
  // data : Vec<u8>,
}

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