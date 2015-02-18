pub use macaroons::KEYBYTES;
pub use macaroons::token::{Token, Signature};
pub use macaroons::caveat::Caveat;

#[derive(Copy)]
pub struct Key(pub [u8; KEYBYTES]);

pub struct Builder {
  token: Token
}

impl Builder {
  pub fn new(key: Key, identifier: Vec<u8>, location: Vec<u8>) -> Builder {
    let token = Token { 
      identifier: identifier,
      location:   location,
      caveats:    None,
      signature:  Signature([0; KEYBYTES]) // TODO: sign tokens
    };

    Builder { token: token }
  }
}
