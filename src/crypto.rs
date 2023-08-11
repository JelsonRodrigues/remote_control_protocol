use std::io::{Write, Read};
use openssl_sys::AES_BLOCK_SIZE;

pub fn get_initialized_buffer(size:usize) -> Vec<u8> {
  let mut vec : Vec<u8> = Vec::with_capacity(size);
  (0..size).for_each(|_| vec.push(0));
  vec
}

pub fn get_random_initialized_buffer(size:usize) -> Vec<u8> {
  let mut vec : Vec<u8> = get_initialized_buffer(size);
  openssl::rand::rand_bytes(&mut vec).unwrap();
  vec
}

pub fn encrypt_send_data(stream: &mut std::net::TcpStream, data: &[u8], aes_key_enc: &openssl::aes::AesKey, iv_enc: &mut [u8]) {
  let size = {
    if data.len() <= AES_BLOCK_SIZE as usize {
      AES_BLOCK_SIZE as usize
    }
    else {
      ((data.len() as f64 / AES_BLOCK_SIZE as f64).ceil() * AES_BLOCK_SIZE as f64) as usize
    }
  };
  let mut data_to_encode = get_random_initialized_buffer(size);
  let mut encoded_data = get_initialized_buffer(size);

  data_to_encode[0..data.len()].copy_from_slice(data);
  
  openssl::aes::aes_ige(&data_to_encode, &mut encoded_data, aes_key_enc, iv_enc, openssl::symm::Mode::Encrypt);

  stream.write(&size.to_le_bytes()).unwrap();
  stream.write(&data.len().to_le_bytes()).unwrap();
  stream.write(&encoded_data).unwrap();
}

pub fn decrypt_receiving_data(stream:&mut std::net::TcpStream, data: &mut Vec<u8>, aes_key_dec: &openssl::aes::AesKey, iv_dec: &mut [u8]) {
  let mut size_bytes = [0_u8; 8];
  stream.read_exact(&mut size_bytes).unwrap();
  let size_to_read = usize::from_le_bytes(size_bytes);
  stream.read_exact(&mut size_bytes).unwrap();
  let usable_size = usize::from_le_bytes(size_bytes);

  let mut buffer = get_initialized_buffer(size_to_read);
  stream.read_exact(&mut buffer).unwrap();

  let mut buffer_dec = get_initialized_buffer(size_to_read);
  openssl::aes::aes_ige(&buffer, &mut buffer_dec, aes_key_dec, iv_dec, openssl::symm::Mode::Decrypt);

  data.reserve_exact(usable_size);

  if data.len() < usable_size {
    let difference = usable_size - data.len() ;
    for _ in 0..difference {
      data.push(0);
    }
  }
  (0..usable_size).for_each(|index| {
    data[index] = buffer_dec[index];
  });
}