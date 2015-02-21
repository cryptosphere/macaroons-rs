pub use caveat::Caveat;
pub use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag};
use sodiumoxide::crypto::auth::hmacsha256::authenticate;

// Macaroons personalize the HMAC key using this string
// "macaroons-key-generator" padded to 32-bytes with zeroes
const KEY_GENERATOR: [u8; 32] = [0x6d,0x61,0x63,0x61,0x72,0x6f,0x6f,0x6e
                                ,0x73,0x2d,0x6b,0x65,0x79,0x2d,0x67,0x65
                                ,0x6e,0x65,0x72,0x61,0x74,0x6f,0x72,0x00
                                ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];

pub struct Token {
  pub identifier: Vec<u8>,
  pub location:   Vec<u8>,
  pub caveats:    Option<Vec<Caveat>>,
  pub tag:        Tag
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
}
