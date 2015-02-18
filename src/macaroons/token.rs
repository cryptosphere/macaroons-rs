pub use macaroons::SIGNATUREBYTES;
pub use macaroons::caveat::Caveat;

#[derive(Copy)]
pub struct Signature(pub [u8; SIGNATUREBYTES]);

pub struct Token {
  pub identifier: Vec<u8>,
  pub location:   Vec<u8>,
  pub caveats:    Option<Vec<Caveat>>,
  pub signature:  Signature
}
