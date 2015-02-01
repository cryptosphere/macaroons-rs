pub use macaroons::caveat::*;

pub const SIGNATUREBYTES: usize = 32;

#[derive(Copy)]
pub struct Signature(pub [u8; SIGNATUREBYTES]);

pub struct Token {
  identifier: Vec<u8>,
  location: Vec<u8>,
  caveats: Vec<Caveat>,
  signature: Signature
}
