// pub const ADDRESS:std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;
pub const ADDRESS:std::net::Ipv4Addr = std::net::Ipv4Addr::new(0, 0, 0, 0);
// pub const PORT_CLIENT:u16 = 5823;
pub const PORT_SERVER:u16 = 5824;
pub const BUFFER_SIZE:usize = 1 << 11;
// pub const CLIENT_ADDR_SOCKET: std::net::SocketAddrV4 = std::net::SocketAddrV4::new(ADDRESS, PORT_CLIENT);
pub const SERVER_ADDR_SOCKET: std::net::SocketAddrV4 = std::net::SocketAddrV4::new(ADDRESS, PORT_SERVER);
pub const RSA_KEY_SIZE : u32 = 1024;

pub fn dec_aes(input:&[u8], out:&mut [u8], bytes_to_decrypt:usize, dec_key:&openssl::aes::AesKey, iv : &[u8]) -> usize {
  let mut len_message_bytes = [0_u8; 8];
  let len_message:usize;

  let mut iv_clone = [0_u8; 32];
  iv_clone.copy_from_slice(&iv);
  
  openssl::aes::aes_ige(&input[..bytes_to_decrypt], &mut out[..bytes_to_decrypt], dec_key, &mut iv_clone, openssl::symm::Mode::Decrypt);

  len_message_bytes.copy_from_slice(&out[bytes_to_decrypt-8..bytes_to_decrypt]);
  len_message = usize::from_be_bytes(len_message_bytes);

  return len_message;
}

pub fn enc_aes(input:&mut [u8], out:&mut [u8], bytes_to_encrypt:usize, enc_key:&openssl::aes::AesKey, iv : &[u8]) -> usize {
  let needed_size = ((bytes_to_encrypt + 8) as f32 / 16.0).ceil() as usize * 16;
  
  if out.len() < needed_size {
    panic!("Output buffer is too small");
  }
  else if input.len() < needed_size  {
    panic!("Input buffer is too small for the bytes + 8 bytes");
  }
  
  // Randomize padding data
  openssl::rand::rand_bytes(&mut input[bytes_to_encrypt..needed_size]).unwrap();
  
  // Save in the last block, in the last 8 bytes the size of the message
  input[needed_size-8..needed_size].copy_from_slice(&bytes_to_encrypt.to_be_bytes());

  let mut iv_clone = [0_u8; 32];
  iv_clone.copy_from_slice(&iv);
  openssl::aes::aes_ige(&input[..needed_size], &mut out[..needed_size], enc_key, &mut iv_clone, openssl::symm::Mode::Encrypt);

  return needed_size;
}