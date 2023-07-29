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
