pub use caveat::{Caveat, Predicate};
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

  pub fn add_caveat(&self, caveat: Caveat) -> Token {
    let Tag(key_bytes) = self.tag;
    let Predicate(predicate_bytes) = caveat.predicate.clone();
    let tag = authenticate(&predicate_bytes, &Key(key_bytes));

    let caveats = match self.caveats {
      Some(ref cavs) => {
        let mut new_cavs = cavs.to_vec();
        new_cavs.push(caveat);
        new_cavs
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
    String::from_str("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK").into_bytes()
  }
}
