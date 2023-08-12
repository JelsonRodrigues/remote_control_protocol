pub mod common;

pub mod message;

use std::io::{Read, Write};
// use rsautogui::keyboard::*;

fn main() {
  let mut server_state : message::ServerStates = message::ServerStates::WaitingForConnection;
  println!("SERVER");

  let socket_tcp = std::net::TcpListener::bind(common::SERVER_ADDR_SOCKET);

  let socket = match socket_tcp {
    Ok(socket) => socket,
    Err(err) => {
      eprintln!("Error creating TCP Listener on addres {}:{}, error {}", common::ADDRESS, common::PORT_SERVER, err);
      std::process::exit(-1);
    },
  };

  // Gen RSA keys
  let (rsa_private, rsa_public_der_bytes) = {
    let rsa_key = openssl::rsa::Rsa::generate(common::RSA_KEY_SIZE);
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
  };

  println!("Key {:?}, der_len {:?}", rsa_private, rsa_public_der_bytes.len());

  let mut sequence_send = 0;
  let mut sequence_received = 0;
  let mut buffer_encripted = [0_u8; common::BUFFER_SIZE];
  let mut buffer_decripted = [0_u8; common::BUFFER_SIZE];

  // println!("size key? {}", rsa_private.size());
  // std::process::exit(0);

  for conection in socket.incoming() {
    if let Ok(mut conection) = conection {
      server_state = message::ServerStates::ExchangingKeys;
      
      let message = message::Message::new(
        message::MessageType::Server(message::ServerMessages::PubKey { der_bytes: rsa_public_der_bytes.clone() }),
        sequence_send
      );
      sequence_send += 1;

      conection.write(&message.ser()).unwrap();

      // Wating for simetric keys
      let size = conection.read(&mut buffer_encripted).unwrap();
      println!("got size = {size}");

      let key_bytes = rsa_private.size() as usize;
      let max_size = (key_bytes - 11) as usize; // 11 bytes of PKCS1 overhead

      let mut dec_helper = [0_u8; common::RSA_KEY_SIZE as usize / 8];

      let message_size = buffer_encripted[0..size]
        .chunks(key_bytes)
        .zip(buffer_decripted.chunks_mut(max_size))
        .map(|(enc, dec)| {
          let size = rsa_private.private_decrypt(
                enc,
                &mut dec_helper,
                openssl::rsa::Padding::PKCS1
              ).unwrap();
              dec[0..size].copy_from_slice(&dec_helper[0..size]);
              size
        })
        .reduce(|sum, value| { sum + value }).unwrap();

      let message_got = message::Message::des(&buffer_decripted[0..message_size]).unwrap();
      println!("SERVER GOT: {:?}", message_got);
    }
  }
  println!("listening");
  return;

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
}

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