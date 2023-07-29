use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Point {
  x: i32,
  y: i32,
}

impl Point {
  pub fn new(x:i32, y:i32) -> Self {
    Self {x, y}
  }

  pub fn x(&self) -> i32 { self.x }
  pub fn y(&self) -> i32 { self.y }

  #[cfg(feature = "cbor")]
  pub fn ser(&self) -> Vec<u8> {
    serde_cbor::ser::to_vec(&self).expect("Unable to serialize!!!")
  }

  #[cfg(feature = "cbor")]
  pub fn des(slice: &[u8]) -> Option<Self>  {
    let res = serde_cbor::de::from_slice::<Self>(slice);
    match res {
      Ok(point) => Some(point),
      Err(_) => None,
    }
  }

  #[cfg(feature = "bincode")]
  pub fn ser(&self) -> Vec<u8> {
    bincode::serialize(&self).expect("Unable to serialize!!!")
  }

  #[cfg(feature = "bincode")]
  pub fn des(slice: &[u8]) -> Option<Self> {
    let res = bincode::deserialize::<Self>(slice);
    match res {
      Ok(point) => Some(point),
      Err(_) => None,
    }
  }
}