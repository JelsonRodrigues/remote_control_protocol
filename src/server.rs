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
    
    println!("RECEIVED: {:?}", buffer[0..received].to_vec());

    let deserialized_point = serde_cbor::de::from_slice::<point::Point>(&buffer[0..received]);
    match deserialized_point {
        Ok(pos) => {
          println!("POINT: {:?}", pos);
          rsautogui::mouse::move_rel(pos.x(), pos.y());
        },
        Err(err) => println!("{err}"),
    }
    

    // Abre o explorador de arquivos
    // key_down(Vk::LeftWin);
    // key_tap(Vk::R);
    // key_up(Vk::LeftWin);

  }
}