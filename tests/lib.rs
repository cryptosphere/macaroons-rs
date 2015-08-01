extern crate macaroons;
pub use macaroons::token::{Token, Tag};
pub use macaroons::caveat::{Caveat, Predicate};
pub use macaroons::verifier::Verifier;

const EMPTY_TAG:    [u8; 32] = [0xe3,0xd9,0xe0,0x29,0x08,0x52,0x6c,0x4c
                               ,0x00,0x39,0xae,0x15,0x11,0x41,0x15,0xd9
                               ,0x7f,0xdd,0x68,0xbf,0x2b,0xa3,0x79,0xb3
                               ,0x42,0xaa,0xf0,0xf6,0x17,0xd0,0x55,0x2f];

const EXPECTED_TAG: [u8; 32] = [0x19,0x7b,0xac,0x7a,0x04,0x4a,0xf3,0x33
                               ,0x32,0x86,0x5b,0x92,0x66,0xe2,0x6d,0x49
                               ,0x3b,0xdd,0x66,0x8a,0x66,0x0e,0x44,0xd8
                               ,0x8c,0xe1,0xa9,0x98,0xc2,0x3d,0xbd,0x67];

fn example_key() -> Vec<u8> {
  Vec::from("this is our super secret key; only we should know it")
}

fn invalid_key() -> Vec<u8> {
  Vec::from("this is not the key you are looking for; it is evil")
}

fn example_id() -> Vec<u8> {
  Vec::from("we used our secret key")
}

fn example_uri() -> Vec<u8> {
  Vec::from("http://mybank/")
}

fn example_predicate() -> Predicate {
  Predicate(Vec::from("test = caveat"))
}

fn example_token() -> Token {
  let token = Token::new(&example_key(), example_id(), example_uri());
  token.add_caveat(Caveat::new(example_predicate()))
}

fn example_serialized() -> Vec<u8> {
  Vec::from("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK")
}

#[test]
fn empty_macaroon_signature() {
  let token = Token::new(&example_key(), example_id(), example_uri());
  let Tag(actual_tag) = token.tag;

  assert_eq!(EMPTY_TAG, actual_tag)
}

#[test]
fn signature_with_first_party_caveat() {
  let Tag(actual_tag) = example_token().tag;
  assert_eq!(EXPECTED_TAG, actual_tag)
}

#[test]
fn binary_serialization() {
  assert_eq!(example_serialized(), example_token().serialize());
}

#[test]
fn binary_deserialization() {
  let token = Token::deserialize(example_serialized()).unwrap();

  assert_eq!(example_uri(), token.location);
  assert_eq!(example_id(),  token.identifier);

  let Tag(actual_tag) = token.tag;
  assert_eq!(EXPECTED_TAG, actual_tag)
}

#[test]
fn simple_verification() {
  let token = example_token();

  assert!(token.verify(&example_key()), "verifies with valid key");
  assert!(!token.verify(&invalid_key()), "doesn't verify with invalid key");
}

#[test]
fn verifying_predicates() {
  let token = example_token();

  let matching_verifier = Verifier::new(|_predicate| { true });
  assert!(matching_verifier.verify(&example_key(), &token));
  assert!(!matching_verifier.verify(&invalid_key(), &token));

  let non_matching_verifier = Verifier::new(|_predicate| { false });
  assert!(!non_matching_verifier.verify(&example_key(), &token));
  assert!(!non_matching_verifier.verify(&invalid_key(), &token));
}
