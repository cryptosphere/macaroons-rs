#![crate_name = "macaroons"]
#![crate_type = "lib"]

#![feature(core)]
#![feature(collections)]

pub mod caveat;
pub use caveat::{Caveat, Predicate};
pub use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag};

extern crate sodiumoxide;
use sodiumoxide::crypto::auth::hmacsha256::authenticate;

extern crate "rustc-serialize" as serialize;
use serialize::base64::{self, FromBase64, ToBase64};

// Macaroons personalize the HMAC key using this string
// "macaroons-key-generator" padded to 32-bytes with zeroes
const KEY_GENERATOR: [u8; 32] = [0x6d,0x61,0x63,0x61,0x72,0x6f,0x6f,0x6e
                                ,0x73,0x2d,0x6b,0x65,0x79,0x2d,0x67,0x65
                                ,0x6e,0x65,0x72,0x61,0x74,0x6f,0x72,0x00
                                ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];

const PACKET_PREFIX_LENGTH: usize = 4;
const MAX_PACKET_LENGTH:    usize = 65535;

pub struct Token {
  pub location:   Vec<u8>,
  pub identifier: Vec<u8>,
  pub caveats:    Option<Vec<Caveat>>,
  pub tag:        Tag
}

struct Packet {
  pub field: Vec<u8>,
  pub value: Vec<u8>
}

impl Token {
  pub fn new(key: Vec<u8>, identifier: Vec<u8>, location: Vec<u8>) -> Token {
    let Tag(personalized_key) = authenticate(&key, &Key(KEY_GENERATOR));
    let tag = authenticate(&identifier, &Key(personalized_key));

    Token {
      identifier: identifier,
      location:   location,
      caveats:    None,
      tag:        tag
    }
  }

  pub fn deserialize(macaroon: Vec<u8>) -> Vec<u8> {
    let mut location:   Option<Vec<u8>> = None;
    //let mut identifier: Option<Vec<u8>> = None;

    let mut token_data = macaroon.as_slice().from_base64().unwrap();
    let packet = Token::depacketize(&mut token_data);

    match packet.field.as_slice() {
      b"location" => { location = Some(packet.value) },
      //"identifier" => { identifier = Some(value) },
      _ => ()
    }

    location.unwrap()
  }

  fn depacketize(data: &mut Vec<u8>) -> Packet {
    let length_str = std::str::from_utf8(&data[0 .. PACKET_PREFIX_LENGTH]).unwrap();
    let packet_length: usize = std::num::from_str_radix(length_str, 16).unwrap();

    let mut packet = data[PACKET_PREFIX_LENGTH .. packet_length].to_vec();

    let pos = packet.iter().position(|&byte| byte == 32).unwrap();
    let mut value = packet.split_off(pos);
    value.remove(0);

    // TODO: ensure this is a newline
    value.pop();

    Packet { field: packet, value: value }
  }

  pub fn add_caveat(&self, caveat: Caveat) -> Token {
    let Tag(key_bytes) = self.tag;
    let Predicate(predicate_bytes) = caveat.predicate.clone();
    let tag = authenticate(&predicate_bytes, &Key(key_bytes));

    let caveats = match self.caveats {
      Some(ref old_caveats) => {
        let mut new_caveats = old_caveats.to_vec();
        new_caveats.push(caveat);
        new_caveats
      },
      None => vec![caveat]
    };

    Token {
      identifier: self.identifier.clone(),
      location:   self.location.clone(),
      caveats:    Some(caveats),
      tag:        tag
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    // TODO: estimate capacity and use Vec::with_capacity
    let mut result: Vec<u8> = Vec::new();

    Token::packetize(&mut result, "location",   &self.location);
    Token::packetize(&mut result, "identifier", &self.identifier);

    match self.caveats {
      None => (),
      Some(ref caveats) => {
        for caveat in caveats.iter() {
          let Predicate(predicate_bytes) = caveat.predicate.clone();
          Token::packetize(&mut result, "cid", &predicate_bytes);
        }
      }
    }

    let Tag(signature_bytes) = self.tag;
    let mut signature_vec = Vec::new();
    signature_vec.push_all(&signature_bytes);

    Token::packetize(&mut result, "signature", &signature_vec);

    result.to_base64(base64::URL_SAFE).into_bytes()
  }

  fn packetize(result: &mut Vec<u8>, field: &str, value: &Vec<u8>) {
    let field_bytes: Vec<u8> = String::from_str(field).into_bytes();
    let packet_length = PACKET_PREFIX_LENGTH + field_bytes.len() + value.len() + 2;

    if packet_length > MAX_PACKET_LENGTH {
      panic!("packet too large to serialize");
    }

    let mut pkt_line = format!("{:04x}{} ", packet_length, field).into_bytes();
    result.append(&mut pkt_line);
    result.append(&mut value.clone());
    result.push('\n' as u8);
  }
}
