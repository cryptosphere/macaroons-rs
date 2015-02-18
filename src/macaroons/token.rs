pub use macaroons::{KEYBYTES, SIGNATUREBYTES};
pub use macaroons::caveat::Caveat;
pub use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag};
use sodiumoxide::crypto::auth::hmacsha256::authenticate;


pub struct Token {
  pub identifier: Vec<u8>,
  pub location:   Vec<u8>,
  pub caveats:    Option<Vec<Caveat>>,
  pub tag:        Tag
}

impl Token {
  pub fn new(key: Key, identifier: Vec<u8>, location: Vec<u8>) -> Token {
    let tag = authenticate(&identifier, &key);

    Token {
      identifier: identifier,
      location:   location,
      caveats:    None,
      tag:        tag
    }
  }
}
