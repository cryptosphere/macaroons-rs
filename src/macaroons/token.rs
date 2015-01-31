pub const SIGNATUREBYTES: usize = 32;

#[derive(Copy)]
pub struct Signature(pub [u8; SIGNATUREBYTES]);

struct Token {
  identifier: Vec<u8>,
  location: Vec<u8>,
  // caveats: TBD;
  signature: Signature
}
