pub mod common;

pub mod message;

use std::io::{Read, Write};
// use rsautogui::keyboard::*;

fn main() {
  println!("SERVER");

  let password = "PasswordExample";
  let password_hash = openssl::sha::sha256(password.as_bytes());

  // Gen RSA keys
  let (rsa_private, rsa_public_der_bytes) = gen_rsa_key(common::RSA_KEY_SIZE);

  println!("Key {:?}, der_len {:?}", rsa_private, rsa_public_der_bytes.len());

  let mut buffer_encripted = [0_u8; common::BUFFER_SIZE];
  let mut buffer_decripted = [0_u8; common::BUFFER_SIZE];

  let (
    aes_key_enc, 
    aes_key_dec, 
    iv, 
    (message_send_sequence, message_receive_sequence), 
    (udp_port_server, udp_port_client)
  ) = wait_connections_in_tcp(
    &rsa_private,
    &rsa_public_der_bytes,
    &mut buffer_encripted,
    &mut buffer_decripted,
    &password_hash
  );

  

}

fn wait_connections_in_tcp(
  rsa_private_key: &openssl::rsa::Rsa<openssl::pkey::Private>, 
  rsa_public_der_bytes:&Vec<u8>,
  buffer_encripted : &mut [u8],
  buffer_decripted : &mut [u8],
  passord_hash : &[u8; 32]
) 
  -> (openssl::aes::AesKey, openssl::aes::AesKey, Vec<u8>, (u32, u32), (u16, u16)){
  // Start listening in TCP
  let socket_tcp = std::net::TcpListener::bind(common::SERVER_ADDR_SOCKET);

  let socket = match socket_tcp {
    Ok(socket) => socket,
    Err(err) => {
      eprintln!("Error creating TCP Listener on addres {}:{}, error {}", common::ADDRESS, common::PORT_SERVER, err);
      std::process::exit(-1);
    },
  };

  loop {
    // Handle connections with key exchange
    for conection in socket.incoming() {
      let mut message_send_sequence = 0;
      let mut message_receive_sequence = 0;
      if let Ok(mut conection) = conection {

        // Hanlde key exchange and get simetric keys
        let key_result = handle_key_exchange(
          &mut conection, 
          buffer_encripted, 
          buffer_decripted, 
          rsa_private_key, 
          rsa_public_der_bytes, 
          &mut message_send_sequence, 
          &mut message_receive_sequence);
        
        if let None = key_result { continue; }
        let (aes_key, iv) = key_result.unwrap();

        let aes_key_enc = openssl::aes::AesKey::new_encrypt(&aes_key).unwrap();
        let aes_key_dec = openssl::aes::AesKey::new_decrypt(&aes_key).unwrap();

        let autentication_result = handle_client_autentication(
          &mut conection, 
          buffer_encripted, 
          buffer_decripted, 
          &mut message_send_sequence, 
          &mut message_receive_sequence, 
          &aes_key_enc, 
          &aes_key_dec, 
          &iv,
          &passord_hash,
        );

        if let None = autentication_result { continue; }

        let (autenticated, (udp_port_server, udp_port_client)) = autentication_result.unwrap();

        if !autenticated { continue; }

        println!("Autenticated!");
        conection.shutdown(std::net::Shutdown::Both).unwrap();
        return (aes_key_enc, aes_key_dec, iv, (message_send_sequence, message_receive_sequence), (udp_port_server, udp_port_client));
      }
    }
  }
}

fn handle_key_exchange(
  socket : &mut std::net::TcpStream,
  buffer_encripted : &mut [u8],
  buffer_decripted : &mut [u8],
  rsa_private_key: &openssl::rsa::Rsa<openssl::pkey::Private>,
  rsa_public_der_bytes:&Vec<u8>,
  message_send_sequence : &mut u32,
  message_receive_sequence : &mut u32,
) -> Option<(Vec<u8>, Vec<u8>)>{
  
  // Send Public Key
  let message = message::Message::new(
    *message_send_sequence,
    message::MessageType::Server(message::ServerMessages::PubKey { der_bytes: rsa_public_der_bytes.clone() }),
  );
  *message_send_sequence += 1;
  if let Err(error) = socket.write(&message.ser()) {
    eprintln!("Error sending public keys, error {error}");
    return None;
  };

  // Receive Simetric Key
  let result = socket.read(buffer_encripted);
  if let Err(error) = result {
    eprintln!("Error sending public keys, error {error}");
    return None;
  }

  let size = result.unwrap();

  let key_bytes = common::RSA_KEY_SIZE as usize / 8;
  let max_size = (key_bytes - 11) as usize; // 11 bytes of PKCS1 overhead

  let mut dec_helper = [0_u8; common::RSA_KEY_SIZE as usize / 8]; // Retirar este buffer

  let message_size = buffer_encripted[0..size]
    .chunks(key_bytes)
    .zip(buffer_decripted.chunks_mut(max_size))
    .map(|(enc, dec)| {
      let size = rsa_private_key.private_decrypt(
            enc,
            &mut dec_helper,
            openssl::rsa::Padding::PKCS1
          ).unwrap();
          dec[0..size].copy_from_slice(&dec_helper[0..size]);
          size
    })
    .reduce(|sum, value| { sum + value }).unwrap();

  let result = message::Message::des(&buffer_decripted[0..message_size]);
  if let None = result {
    eprintln!("Error parsing message with simetric keys");
    return None;
  }

  let message = result.unwrap();
  *message_receive_sequence = message.sequence;

  let (aes_key, iv) = match message.message_type {
    message::MessageType::Client(client_message) => {
      match client_message {
        message::ClientMessages::SimKey { key_bytes, iv_bytes } => {
          (key_bytes, iv_bytes)
        },
        _ => {
          eprintln!("Wrong message type received, should received SimKey message");
          return None;
        },
      }
    },
    _ => {
      eprintln!("Wrong message received, should received Client message, intead of Server message");
      return None;
    },
  };
  
  Some((aes_key, iv))
}

fn handle_client_autentication(
  socket : &mut std::net::TcpStream,
  buffer_encripted : &mut [u8],
  buffer_decripted : &mut [u8],
  message_send_sequence : &mut u32,
  message_receive_sequence : &mut u32,
  aes_key_enc : &openssl::aes::AesKey,
  aes_key_dec : &openssl::aes::AesKey,
  iv : &[u8],
  hash_pasword : &[u8; 32],
  ) -> Option<(bool, (u16, u16))> {
  // Autenticate client
  let read_result = socket.read(buffer_encripted);
  if let Err(error) = read_result {
    eprintln!("Error getting the password hash from client, error {error}");
    return None;
  }

  let size = read_result.unwrap();
  let message_size = common::dec_aes( &buffer_encripted, buffer_decripted, size, &aes_key_dec, &iv);

  let result = message::Message::des(&buffer_decripted[..message_size]);
  if let None = result {
    eprintln!("Error parsing message from client");
    return None;
  }

  let message = result.unwrap();
  *message_receive_sequence = message.sequence;

  let (hash, udp_port) = match message.message_type {
    message::MessageType::Client(client_message) => {
      match client_message {
        message::ClientMessages::Auth { hashed_password_bytes, upd_port_listening } => (hashed_password_bytes, upd_port_listening),
        _ => {
          eprintln!("Wrong message type received, expected Auth message");
          return None;
        },
      }
    },
    _ => {
      eprintln!("Wrong message received, expected Client Auth message, not a Server message");
      return None;
    },
  };

  let comp = |real_hash:&[u8], comparing_hash:&[u8]| -> bool {
    for (h1, h2) in real_hash.iter().zip(comparing_hash.iter()) {
      if h1 != h2 { return false; }
    }
    return true;
  };

  let auth = comp(hash_pasword, &hash);
  if !auth {
    // send access denied
    let denied = message::Message::new(*message_send_sequence, message::MessageType::Server(message::ServerMessages::AccessDenied));
    *message_send_sequence += 1;

    let denied_serialized = denied.ser();
    buffer_decripted[0..denied_serialized.len()].copy_from_slice(&denied_serialized);

    let size_encripted = common::enc_aes(buffer_decripted,  buffer_encripted, denied_serialized.len(), &aes_key_enc, &iv);

    let result = socket.write(&buffer_encripted[0..size_encripted]);

    if let Err(error) = result {
      eprintln!("Error sendind AccessDenied message, error {error}");
      return None;
    }

    return Some((false, (0, 0)));
  }

  // send Acces granted
  let udp_port_server = 5936;

  let granted = message::Message::new(*message_send_sequence, message::MessageType::Server(message::ServerMessages::AccessGranted { upd_port_listening: udp_port_server }));
  *message_send_sequence += 1;
  let granted_coded = granted.ser();

  buffer_decripted[0..granted_coded.len()].copy_from_slice(&granted_coded);

  let size_encripted = common::enc_aes(buffer_decripted,  buffer_encripted, granted_coded.len(), &aes_key_enc, &iv);
  let result = socket.write(&mut buffer_encripted[0..size_encripted]);
  if let Err(error) = result {
    eprintln!("Error sendind AccessDenied message, error {error}");
    return None;
  }

  return Some((true, (udp_port_server, udp_port)));
}

fn gen_rsa_key(key_size:u32) -> (openssl::rsa::Rsa<openssl::pkey::Private>, Vec<u8>) {
  let rsa_key = openssl::rsa::Rsa::generate(key_size);
  let private_key = match rsa_key {
    Ok(private_key) => private_key,
    Err(err) => {
      eprintln!("Error creating the private key, error {}", err);
      std::process::exit(-1);
    },
  };

  let public_key_der_format = private_key.public_key_to_der_pkcs1();
  let public_key_der_format_bytes = match public_key_der_format {
    Ok(der_bytes) => der_bytes,
    Err(err) => {
      eprintln!("Error formatting public key as DER, error {}", err);
      std::process::exit(-1);
    }
  };
  (private_key, public_key_der_format_bytes)
}

fn handle_messages_in_udp() {
  // Start listen in UDP port specified

  // For each message verify if the sequence number is correct, 
  // if not, send a message requesting that number
  // else just do the action specified in the message
  todo!()
}
  /*
  let a = std::net::UdpSocket::bind(
    std::net::SocketAddrV4::new(common::ADDRESS, common::PORT_SERVER)
  ).expect("ERROR OPENING SOCKET");
  
  let mut buffer = vec![0_u8; common::BUFFER_SIZE];
  loop {
    let received = a.recv(&mut buffer).expect("Unable to receive data!!!");
    // println!("RECEIVED: {:?}", buffer[0..received].to_vec());
    let bef  = std::time::Instant::now();

    if let Some(pos) = point::Point::des(&buffer[0..received]) {
      let after  = std::time::Instant::now();
      rsautogui::mouse::move_rel(pos.x(), pos.y());
      println!("{:?}", (after - bef));
    }
    
    // let deserialized_point = serde_cbor::de::from_slice::<point::Point>(&buffer[0..received]);
    // match deserialized_point {
    //     Ok(pos) => {
    //       println!("POINT: {:?}", pos);
    //       rsautogui::mouse::move_rel(pos.x(), pos.y());
    //     },
    //     Err(err) => println!("{err}"),
    // }
    

    // Abre o explorador de arquivos
    // key_down(Vk::LeftWin);
    // key_tap(Vk::R);
    // key_up(Vk::LeftWin);

  }

   */


/*

// Generate a random uuid
// encrypt the ID
// Send it to the client

use std::{net::{SocketAddrV4, TcpStream}, io::{Write, Read}};
use openssl::aes::AesKey;

pub mod commom;
use commom::*;

fn main() {
    println!("This is the Server side");

    // Generate uuid
    let server_uuid = generate_uuid();
    println!("server - UUID: {server_uuid}");

    // Create listener
    let listener = std::net::TcpListener::bind(SocketAddrV4::new(ADDRESS, PORT))
        .expect("Unable to create listener!!");
    println!("IP: {}", listener.local_addr().unwrap());

    loop {
        for item in listener.incoming() {
            if let Ok(stream) = item {
                handle_connection(stream);
            }
        }
    }
}

fn generate_uuid() -> uuid::Uuid {
    return uuid::Uuid::new_v4();
}

fn handle_connection(mut stream: TcpStream){
    let addr = stream.peer_addr().expect("Error");
    println!("Address incoming {addr}");

    let (aes_key, iv) = handle_security_protocol(&mut stream);

    let aes_key_enc = openssl::aes::AesKey::new_encrypt(&aes_key).unwrap();
    let aes_key_dec = openssl::aes::AesKey::new_decrypt(&aes_key).unwrap();

    let mut iv_enc = iv.clone();
    let mut iv_dec = iv.clone();

    handle_send_random_uuid_request(&mut stream, &aes_key_enc, &mut iv_enc);

    // Get the Number of Request and display
    let mut buffer: Vec<u8> = Vec::new();
    let mut number_bytes = [0_u8; 8];
    for _ in 0..NUMBERS_TO_SEND {
        decrypt_receiving_data(&mut stream, &mut buffer, &aes_key_dec, &mut iv_dec);
        number_bytes.copy_from_slice(&buffer[..8]);
        let number = i64::from_le_bytes(number_bytes);
        println!("Number {number}");
    }

    for _ in 0..NUMBERS_TO_SEND {
        send_random_number(&mut stream, &aes_key_enc, &mut iv_enc);
    }
    
}

fn send_random_number(stream: &mut std::net::TcpStream, aes_key_enc: &openssl::aes::AesKey, iv_enc: &mut [u8]) {
    let number_to_send:i64 = rand::random::<i64>() % 2048 + 10000;
    encrypt_send_data(stream, &number_to_send.to_le_bytes(), &aes_key_enc, iv_enc);
    println!("Number sent {number_to_send}");
}

fn handle_send_random_uuid_request(stream: &mut TcpStream, aes_enc_key: &AesKey, iv_enc: &mut [u8]) {
    let random_uuid = generate_uuid();
    println!("UUID sent {random_uuid}");
    encrypt_send_data(stream, &random_uuid.to_bytes_le(), aes_enc_key, iv_enc);
}

fn handle_security_protocol(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    // Generate asymetric RSA key
    let rsa_key = openssl::rsa::Rsa::generate(RSA_KEY_SIZE).unwrap();

    // Format as DER
    let der_format = rsa_key.public_key_to_der().unwrap();

    // Send to the client
    stream.write(&der_format.len().to_le_bytes()).unwrap();  // Writes usize bytes and send to client the ammount of data to retrieve from the stream
    stream.write(&der_format).unwrap();

    // Get the bytes of AES Key
    let mut aes_key_bytes_enc: Vec<u8> = get_initialized_buffer(rsa_key.size() as usize);
    stream.read_exact(&mut aes_key_bytes_enc).unwrap();

    // Get the bytes of IV for AES Key
    let mut iv_bytes_enc = get_initialized_buffer(rsa_key.size() as usize);
    stream.read_exact(&mut iv_bytes_enc).unwrap();

    let mut aes_key_bytes: Vec<u8> = get_initialized_buffer(rsa_key.size() as usize);
    let mut iv_bytes: Vec<u8> = get_initialized_buffer(rsa_key.size() as usize);

    let size_key = rsa_key.private_decrypt(&aes_key_bytes_enc, &mut aes_key_bytes, openssl::rsa::Padding::PKCS1).unwrap();
    let size_iv = rsa_key.private_decrypt(&iv_bytes_enc, &mut iv_bytes, openssl::rsa::Padding::PKCS1).unwrap();

    aes_key_bytes.truncate(size_key);
    iv_bytes.truncate(size_iv);

    (aes_key_bytes, iv_bytes)
}

*/