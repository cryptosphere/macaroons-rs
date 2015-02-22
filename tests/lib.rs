#![feature(collections)]

extern crate macaroons;
pub use macaroons::token::{Token, Tag};
pub use macaroons::caveat::{Caveat, Predicate};

fn example_key() -> Vec<u8> {
  String::from_str("this is our super secret key; only we should know it").into_bytes()
}

fn example_id() -> Vec<u8> {
  String::from_str("we used our secret key").into_bytes()
}

fn example_uri() -> Vec<u8> {
  String::from_str("http://mybank/").into_bytes()
}

fn example_predicate() -> Predicate {
  Predicate(String::from_str("test = caveat").into_bytes())
}

#[test]
fn empty_macaroon_signature() {
  let token = Token::new(example_key(), example_id(), example_uri());

  let expected_tag = [0xe3,0xd9,0xe0,0x29,0x08,0x52,0x6c,0x4c
                     ,0x00,0x39,0xae,0x15,0x11,0x41,0x15,0xd9
                     ,0x7f,0xdd,0x68,0xbf,0x2b,0xa3,0x79,0xb3
                     ,0x42,0xaa,0xf0,0xf6,0x17,0xd0,0x55,0x2f];

  let Tag(actual_tag) = token.tag;
  assert_eq!(expected_tag, actual_tag)
}

#[test]
fn signature_with_first_party_caveat() {
  let token = Token::new(example_key(), example_id(), example_uri());
  let new_token = token.add_caveat(Caveat::new(example_predicate()));

  let expected_tag = [0x19,0x7b,0xac,0x7a,0x04,0x4a,0xf3,0x33
                     ,0x32,0x86,0x5b,0x92,0x66,0xe2,0x6d,0x49
                     ,0x3b,0xdd,0x66,0x8a,0x66,0x0e,0x44,0xd8
                     ,0x8c,0xe1,0xa9,0x98,0xc2,0x3d,0xbd,0x67];

  let Tag(actual_tag) = new_token.tag;
  assert_eq!(expected_tag, actual_tag)
}

#[test]
fn binary_serialization() {
  let token = Token::new(example_key(), example_id(), example_uri());
  let new_token = token.add_caveat(Caveat::new(example_predicate()));

  let expected_macaroon = String::from_str("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK").into_bytes();
  assert_eq!(expected_macaroon, new_token.serialize());
}
