pub mod common;
pub mod point;

use rsautogui::keyboard::*;

fn main() {
  println!("SERVER");

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