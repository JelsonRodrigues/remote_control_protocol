pub mod common;
pub mod message;

use std::io::{Read, Write};

fn main() {
  println!("SERVER");
 
  let password_hash = loop {
    println!("Set SERVER password");
    let mut password = String::new();
    let result = std::io::stdin().read_line(&mut password);
    if let Err(error) = result {
      eprintln!("Error reading the password!!");
      continue;
    }
    
    println!("Password {password}");
    break openssl::sha::sha256(password.trim_end().as_bytes());
  };

  // Gen RSA keys
  let (rsa_private, rsa_public_der_bytes) = gen_rsa_key(common::RSA_KEY_SIZE);

  println!("Key {:?}, der_len {:?}", rsa_private, rsa_public_der_bytes.len());

  let mut buffer_encripted = [0_u8; common::BUFFER_SIZE];
  let mut buffer_decripted = [0_u8; common::BUFFER_SIZE];

  loop {
    println!("Listening TCP!");
    let (
      aes_key_enc, 
      aes_key_dec, 
      iv, 
      (mut message_send_sequence, mut message_receive_sequence), 
      (udp_port_server, client_socket_addr)
    ) = wait_connections_in_tcp(
      &rsa_private,
      &rsa_public_der_bytes,
      &mut buffer_encripted,
      &mut buffer_decripted,
      &password_hash
    );

    println!("Listening UDP!");
    handle_messages_in_udp(
      &aes_key_enc,
      &aes_key_dec,
      &iv,
      udp_port_server,
      &client_socket_addr,
      &mut message_send_sequence,
      &mut message_receive_sequence,
      &mut buffer_encripted,
      &mut buffer_decripted,
    );
  }

}

fn wait_connections_in_tcp(
  rsa_private_key: &openssl::rsa::Rsa<openssl::pkey::Private>, 
  rsa_public_der_bytes:&Vec<u8>,
  buffer_encripted : &mut [u8],
  buffer_decripted : &mut [u8],
  passord_hash : &[u8; 32]
) 
  -> (openssl::aes::AesKey, openssl::aes::AesKey, Vec<u8>, (u32, u32), (u16, std::net::SocketAddr)){
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
        let result = conection.peer_addr();
        if let Err(error) = result {
          eprintln!("Error getting the IP and PORT of the remote conection, error {error}");
          continue;
        }
        let mut socket_client = result.unwrap();

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
        socket_client.set_port(udp_port_client);

        if !autenticated { continue; }

        println!("Autenticated!");
        conection.shutdown(std::net::Shutdown::Both).unwrap();
        return (aes_key_enc, aes_key_dec, iv, (message_send_sequence, message_receive_sequence), (udp_port_server, socket_client));
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
    eprintln!("Error reading simetric key bytes, error {error}");
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

fn handle_messages_in_udp(
  aes_key_enc: &openssl::aes::AesKey,
  aes_key_dec: &openssl::aes::AesKey,
  iv: &Vec<u8>,
  udp_port_server : u16,
  client_socket_addr : &std::net::SocketAddr,
  message_send_sequence : &mut u32,
  message_receive_sequence : &mut u32,
  buffer_encripted : &mut [u8],
  buffer_decripted : &mut [u8],
) {
  // Start listen in UDP port specified
  let result = std::net::UdpSocket::bind(
    std::net::SocketAddrV4::new(common::ADDRESS, udp_port_server)
  );
  if let Err(error) = result {
    eprintln!("Error binding to the UDP socket, error {error}");
    return;
  }
  let socket = result.unwrap();

  loop {
    let result = socket.recv(buffer_encripted);
    if let Err(error) = result {
      eprintln!("Error getting data from the socket, error {error}");
      return;
    }

    let size = result.unwrap();
    let message_size = common::dec_aes(buffer_encripted, buffer_decripted, size, aes_key_dec, iv);
    let result = message::Message::des(&buffer_decripted[..message_size]);
    if let None = result {
      eprintln!("Error parsing the message");
      continue;
    }

    let message = result.unwrap();

    if message.sequence -1 != *message_receive_sequence {
      // Send request message
      let message = message::Message::new(*message_send_sequence, message::MessageType::Server(message::ServerMessages::RequestSend { sequence_requested: *message_receive_sequence }));
      *message_send_sequence += 1;
      let message_serialized = message.ser();
      
      buffer_decripted[..message_serialized.len()].copy_from_slice(&message_serialized);
      let size = common::enc_aes(buffer_decripted, buffer_encripted, message_serialized.len(), aes_key_enc, iv);

      let result = socket.send_to(&buffer_encripted[..size], client_socket_addr);
      if let Err(error) = result {
        eprintln!("Error sending request message, error {error}");
        return;
      }
      continue;
    }
    else {
      // Send Ack
      let ack_message = message::Message::new(*message_send_sequence, message::MessageType::Server(message::ServerMessages::Ack { sequence_aknowledgement: message.sequence }));
      *message_send_sequence += 1;
      let message_serialized = ack_message.ser();
      
      buffer_decripted[..message_serialized.len()].copy_from_slice(&message_serialized);
      let size = common::enc_aes(buffer_decripted, buffer_encripted, message_serialized.len(), aes_key_enc, iv);

      let result = socket.send_to(&buffer_encripted[..size], client_socket_addr);
      if let Err(error) = result {
        eprintln!("Error sending Ack message, error {error}");
        return;
      }
    }

    *message_receive_sequence = message.sequence;
    
    match message.message_type {
      message::MessageType::Client(client_message) => {
        match client_message {
          message::ClientMessages::MovePointer { x, y } => {
            // rsautogui::mouse::move_rel(x, y);
            let currrent_pos = autopilot::mouse::location();
            let new_pos = autopilot::geometry::Point::new(currrent_pos.x + x as f64, currrent_pos.y + y as f64);
            let result = autopilot::mouse::move_to(new_pos);
            if let Err(error) = result {
              eprintln!("An error occurred while moving the mouse, error {error}");
            }
          },
          message::ClientMessages::PressKey { key_codes } => {
            for i in key_codes {
              if i <= 42 && i > 0 {
                eprintln!("Cannot press key {i} yet");
                // autopilot::key::tap(
                  // &autopilot::key::Code(i), &[], 0, 0);
              }
              let result = char::from_u32(i as u32);
              if let Some(char) = result {
                let character = autopilot::key::Character(char);
                autopilot::key::tap(&character, &[], 0, 0);
              }
            }
          },
          message::ClientMessages::RunCommand { string_bytes } => {
            eprintln!("Not implemented");
            let result = String::from_utf8(string_bytes);
            match result {
              Ok(comand) =>  {
                let has_args = comand.find(" ");
                if let Some(location) = has_args {
                  let (program, args)= comand.split_at(location);
                  println!("command: {program}");
                  let result = std::process::Command::new(program)
                              .arg(args)
                              .spawn();
                  if let Err(error) = result {
                    eprintln!{"Unable to run the command. Error {error}"};
                  }
                }
                else {
                  println!("command: {comand}");
                  let result = std::process::Command::new(comand)
                              .spawn();
                  if let Err(error) = result {
                    eprintln!{"Unable to run the command. Error {error}"};
                  }
                }
              },
              Err(error) => {
                eprintln!("Failed to parse string, error {error}");
              },
            } 
          },
          message::ClientMessages::Quit => { return; },
          _ => {
            eprintln!("Message is of wrong type, shouldnt receive Auth/SimKey message now!");
            continue;
          }
        }
      },
      message::MessageType::Server(_) => {
        eprintln!("Message is of wrong type, should receive Client message instead of Server message!");
        continue;
      },
    }
  }
}