#![crate_name = "macaroons"]
#![crate_type = "lib"]

#![feature(core)]
#![feature(collections)]

use std::slice::bytes;

pub mod caveat;
pub use caveat::{Caveat, Predicate};
pub use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag, TAGBYTES};

extern crate sodiumoxide;
use sodiumoxide::crypto::auth::hmacsha256::authenticate;

extern crate "rustc-serialize" as serialize;
use serialize::base64::{self, FromBase64, ToBase64};

// Macaroons personalize the HMAC key using this string
// "macaroons-key-generator" padded to 32-bytes with zeroes
const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

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
    let Tag(personalized_key) = authenticate(&key, &Key(*KEY_GENERATOR));
    let tag = authenticate(&identifier, &Key(personalized_key));

    Token {
      location:   location,
      identifier: identifier,
      caveats:    None,
      tag:        tag
    }
  }

  pub fn deserialize(macaroon: Vec<u8>) -> Token {
    let mut location:   Option<Vec<u8>> = None;
    let mut identifier: Option<Vec<u8>> = None;
    let mut caveats:    Vec<Caveat>     = Vec::new();
    let mut tag:        Option<Tag>     = None;

    let token_data = macaroon.as_slice().from_base64().unwrap();
    let mut index: usize = 0;

    while index < token_data.len() {
      let (packet, taken) = Token::depacketize(&token_data, index);
      index += taken;

      match packet.field.as_slice() {
        b"location"   => { location = Some(packet.value) },
        b"identifier" => { identifier = Some(packet.value) },
        b"cid"        => { caveats.push(Caveat::new(Predicate(packet.value))) },
        b"signature"  => {
          if packet.value.len() != TAGBYTES {
            panic!("invalid signature length")
          }

          let mut signature_bytes = [0u8; TAGBYTES];
          bytes::copy_memory(&mut signature_bytes, &packet.value[..TAGBYTES]);

          tag = Some(Tag(signature_bytes))
        },
        _ => { panic!("unrecognized packet type"); }
      }
    }

    Token {
      location:   location.unwrap(),
      identifier: identifier.unwrap(),
      caveats:    if caveats.is_empty() { None } else { Some(caveats) },
      tag:        tag.unwrap()
    }
  }

  fn depacketize(data: &Vec<u8>, index: usize) -> (Packet, usize) {
    let length_str = std::str::from_utf8(&data[index .. index + PACKET_PREFIX_LENGTH]).unwrap();
    let packet_length: usize = std::num::from_str_radix(length_str, 16).unwrap();

    let mut packet_bytes = data[index + PACKET_PREFIX_LENGTH .. index + packet_length].to_vec();

    let pos = packet_bytes.iter().position(|&byte| byte == b' ').unwrap();
    let mut value = packet_bytes.split_off(pos);
    value.remove(0);

    if value.pop().unwrap() != b'\n' {
      panic!("unexpected character at end of pkt-line");
    }

    let packet = Packet { field: packet_bytes, value: value };
    (packet, packet_length)
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
