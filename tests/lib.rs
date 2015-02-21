#![feature(collections)]

extern crate macaroons;
pub use macaroons::token::{Token, Tag};
pub use macaroons::caveat::Caveat;

const EXAMPLE_KEY: &'static str = "this is our super secret key; only we should know it";
const EXAMPLE_ID:  &'static str = "we used our secret key";
const EXAMPLE_URI: &'static str = "http://mybank/";

#[test]
fn empty_macaroon_signature() {
  let key        = String::from_str(EXAMPLE_KEY).into_bytes();
  let identifier = String::from_str(EXAMPLE_ID).into_bytes();
  let location   = String::from_str(EXAMPLE_URI).into_bytes();

  let token = Token::new(key, identifier, location);

  let expected_tag = [0xe3,0xd9,0xe0,0x29,0x08,0x52,0x6c,0x4c
                     ,0x00,0x39,0xae,0x15,0x11,0x41,0x15,0xd9
                     ,0x7f,0xdd,0x68,0xbf,0x2b,0xa3,0x79,0xb3
                     ,0x42,0xaa,0xf0,0xf6,0x17,0xd0,0x55,0x2f];

  let Tag(actual_tag) = token.tag;
  assert_eq!(expected_tag, actual_tag)
}

#[test]
fn signature_with_first_party_caveat() {
  let key        = String::from_str(EXAMPLE_KEY).into_bytes();
  let identifier = String::from_str(EXAMPLE_ID).into_bytes();
  let location   = String::from_str(EXAMPLE_URI).into_bytes();

  let token     = Token::new(key, identifier, location);
  let predicate = String::from_str("test = caveat").into_bytes();
  let new_token = token.add_caveat(Caveat::new(predicate));

  let expected_tag = [0x19,0x7b,0xac,0x7a,0x04,0x4a,0xf3,0x33
                     ,0x32,0x86,0x5b,0x92,0x66,0xe2,0x6d,0x49
                     ,0x3b,0xdd,0x66,0x8a,0x66,0x0e,0x44,0xd8
                     ,0x8c,0xe1,0xa9,0x98,0xc2,0x3d,0xbd,0x67];

  let Tag(actual_tag) = new_token.tag;
  assert_eq!(expected_tag, actual_tag)
}
