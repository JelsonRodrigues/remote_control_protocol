pub mod common;
pub mod point;

use point::Point;

fn main() {
  println!("CLIENT!");

  let socket = std::net::UdpSocket::bind(
    common::CLIENT_ADDR_SOCKET
  ).expect("ERROR OPENING SOCKET");

  let movement = Point::new(2, 1);
  println!("SEND: {:?}", movement);
  
  // Serialize the struct to a byte buffer
  let serialized = movement.ser();

  println!("SERIALIZED: {:?}", serialized);
  for _ in 0..150 {
    socket.send_to( &serialized, common::SERVER_ADDR_SOCKET).expect("Failed to send message");
  }

  println!("Closing!!!");
}


/*

use std::{net::{SocketAddrV4, TcpStream}, io::{Write, Read}, process::exit};

pub mod commom;
use commom::*;

fn main() {
    println!("This is the Client!!!");

    let connection = std::net::TcpStream::connect(SocketAddrV4::new(ADDRESS, PORT));

    let mut stream: std::net::TcpStream;
    match connection {
        Ok(ok) => stream = ok,
        Err(error) => {
            println!("ERROR occured!! Kind: {}", error.kind());
            println!("{error}");
            exit(-1);
        },
    }

    let (key, iv) = handle_security_protocol(&mut stream); 

    let aes_key_enc = openssl::aes::AesKey::new_encrypt(&key).unwrap();
    let aes_key_dec = openssl::aes::AesKey::new_decrypt(&key).unwrap();

    let mut iv_enc = iv.clone();
    let mut iv_dec = iv.clone();

    let mut uuid_bytes:Vec<u8> = Vec::new();
    decrypt_receiving_data(&mut stream, &mut uuid_bytes, &aes_key_dec, &mut iv_dec);
    
    let mut uuid_bytes_static = [0_u8; 16];
    uuid_bytes_static.copy_from_slice(&uuid_bytes[0..16]);

    let uuid = uuid::Uuid::from_bytes_le(uuid_bytes_static);
    println!("UUID got {uuid}");

    for _ in 0..NUMBERS_TO_SEND {
        send_random_number(&mut stream, &aes_key_enc, &mut iv_enc);
    }

    let mut buffer: Vec<u8> = Vec::new();
    let mut number_bytes = [0_u8; 8];
    for _ in 0..NUMBERS_TO_SEND {
        decrypt_receiving_data(&mut stream, &mut buffer, &aes_key_dec, &mut iv_dec);
        number_bytes.copy_from_slice(&buffer[..8]);
        let number = i64::from_le_bytes(number_bytes);
        println!("Number {number}");
    }
}

fn send_random_number(stream: &mut std::net::TcpStream, aes_key_enc: &openssl::aes::AesKey, iv_enc: &mut [u8]) {
    let number_to_send:i64 = rand::random::<i64>() % 2048;
    encrypt_send_data(stream, &number_to_send.to_le_bytes(), &aes_key_enc, iv_enc);
    println!("Number sent {number_to_send}");
}

fn handle_security_protocol(stream : &mut TcpStream) -> (Vec<u8>, Vec<u8>){
    // Get the public RSA key
    let mut bytes_size = [0_u8; 8];
    stream.read_exact(&mut bytes_size).unwrap();
    let size_to_read = usize::from_le_bytes(bytes_size);
    let mut rsa_public_bytes_der = get_initialized_buffer(size_to_read);
    stream.read_exact(&mut rsa_public_bytes_der).unwrap();

    // Generate the AES key
    let mut key = get_initialized_buffer(AES_KEY_SIZE / 8);
    let mut iv = get_initialized_buffer(AES_KEY_SIZE / 4);
    openssl::rand::rand_bytes(&mut key).unwrap();
    openssl::rand::rand_bytes(&mut iv).unwrap();

    // Send back
    let rsa_key = openssl::rsa::Rsa::public_key_from_der(&rsa_public_bytes_der).unwrap();
    
    let mut key_enc = get_initialized_buffer(rsa_key.size() as usize);
    rsa_key.public_encrypt(&key, &mut key_enc, openssl::rsa::Padding::PKCS1).unwrap();

    let mut iv_enc = get_initialized_buffer(rsa_key.size() as usize);
    rsa_key.public_encrypt(&iv, &mut iv_enc, openssl::rsa::Padding::PKCS1).unwrap();
    
    stream.write_all(&key_enc).unwrap();
    stream.write_all(&iv_enc).unwrap();

    (key, iv)
}
*/