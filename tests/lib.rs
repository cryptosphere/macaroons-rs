extern crate macaroons;
pub use macaroons::token::{Token, Tag};

#[test]
fn empty_macaroon_signature() {
  let key        = String::from_str("this is our super secret key; only we should know it").into_bytes();
  let identifier = String::from_str("we used our secret key").into_bytes();
  let location   = String::from_str("http://mybank/").into_bytes();

  let token = Token::new(key, identifier, location);

  let expected_tag = [0xe3,0xd9,0xe0,0x29,0x08,0x52,0x6c,0x4c
                     ,0x00,0x39,0xae,0x15,0x11,0x41,0x15,0xd9
                     ,0x7f,0xdd,0x68,0xbf,0x2b,0xa3,0x79,0xb3
                     ,0x42,0xaa,0xf0,0xf6,0x17,0xd0,0x55,0x2f];

  let Tag(actual_tag) = token.tag;
  assert_eq!(expected_tag, actual_tag)
}
