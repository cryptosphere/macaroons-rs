extern crate macaroons;

use macaroons::caveat::Caveat;
use macaroons::token::Token;
use macaroons::v1::V1Token;
use macaroons::verifier::{Func, LinkVerifier};

const EMPTY_TAG: [u8; 32] = [0xe3, 0xd9, 0xe0, 0x29, 0x08, 0x52, 0x6c, 0x4c, 0x00, 0x39, 0xae,
                             0x15, 0x11, 0x41, 0x15, 0xd9, 0x7f, 0xdd, 0x68, 0xbf, 0x2b, 0xa3,
                             0x79, 0xb3, 0x42, 0xaa, 0xf0, 0xf6, 0x17, 0xd0, 0x55, 0x2f];

const EXPECTED_TAG_WITH_FIRST_PARTY_CAVEATS: [u8; 32] = [0x19, 0x7b, 0xac, 0x7a, 0x04, 0x4a, 0xf3,
                                                         0x33, 0x32, 0x86, 0x5b, 0x92, 0x66, 0xe2,
                                                         0x6d, 0x49, 0x3b, 0xdd, 0x66, 0x8a, 0x66,
                                                         0x0e, 0x44, 0xd8, 0x8c, 0xe1, 0xa9, 0x98,
                                                         0xc2, 0x3d, 0xbd, 0x67];

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

fn example_first_party_caveat() -> Caveat {
    Caveat::first_party(Vec::from("test = caveat"))
}

fn example_first_party_caveat_different_prefix() -> Caveat {
    Caveat::first_party(Vec::from("other = test"))
}

fn verify_caveat(predicate: &str) -> bool {
    let (prefix, value) = predicate.split_at(7);
    
    if prefix != "test = " {
        return true;
    }

    value == "caveat"
}

fn verify_wrong_value(predicate: &str) -> bool {
    let (prefix, value) = predicate.split_at(7);
    
    if prefix != "test = " {
        return true;
    }

    value == "wrong"
}

fn verify_other(predicate: &str) -> bool {
    let (prefix, value) = predicate.split_at(7);
    
    if prefix != "other = " {
        return true;
    }

    value == "caveat"
}

fn example_caveat_key() -> Vec<u8> {
    Vec::from("4; guaranteed random by a fair toss of the dice")
}

fn example_third_party_caveat_id() -> Vec<u8> {
    Vec::from("this was how we remind auth of key/pred")
}

fn example_third_party_caveat_location() -> Vec<u8> {
    Vec::from("http://auth.mybank/")
}

fn example_third_party_caveat() -> Caveat {
    Caveat::third_party(example_caveat_key(),
                        example_third_party_caveat_id(),
                        example_third_party_caveat_location())
}

fn example_token() -> V1Token {
    V1Token::new(&example_key(), example_id(), Some(example_uri()))
}

fn example_serialized_with_first_party_caveats() -> Vec<u8> {
    Vec::from("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCB\
               rZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDk\
               TYjOGpmMI9vWcK")
}

#[test]
fn empty_macaroon_signature() {
    let token = V1Token::new(&example_key(), example_id(), Some(example_uri()));
    assert_eq!(EMPTY_TAG, token.tag)
}

#[test]
fn signature_with_first_party_caveat() {
    let token = example_token().add_caveat(&example_first_party_caveat());
    assert_eq!(EXPECTED_TAG_WITH_FIRST_PARTY_CAVEATS, token.tag)
}

#[test]
fn signature_with_third_party_caveat() {
    let mut token = example_token();

    token = token.add_caveat(&example_first_party_caveat());
    token = token.add_caveat(&example_third_party_caveat());

    let token_serialized = token.serialize().unwrap();
    let parsed_token = V1Token::deserialize(token_serialized).unwrap();
    let third_party_caveat = &parsed_token.caveats[1];

    assert_eq!(third_party_caveat.caveat_id,
               example_third_party_caveat_id());
    assert_eq!(third_party_caveat.caveat_location,
               Some(example_third_party_caveat_location()));
}

#[test]
fn binary_serialization() {
    let token = example_token().add_caveat(&example_first_party_caveat());
    assert_eq!(example_serialized_with_first_party_caveats(),
               token.serialize().unwrap());
}

#[test]
fn binary_deserialization() {
    let token = V1Token::deserialize(example_serialized_with_first_party_caveats()).unwrap();

    assert_eq!(example_uri(), token.location.unwrap());
    assert_eq!(example_id(), token.identifier);

    assert_eq!(EXPECTED_TAG_WITH_FIRST_PARTY_CAVEATS, token.tag)
}

#[test]
fn simple_verification() {
    let token = example_token().add_caveat(&example_first_party_caveat());

    assert!(token.authenticate_without_verifying(&example_key()).is_ok(), "verifies with valid key");
    assert!(token.authenticate_without_verifying(&invalid_key()).is_err(), "doesn't verify with invalid key");
}

#[test]
fn verifying_predicates() {
    let token = example_token()
        .add_caveat(&example_first_party_caveat())
        .add_caveat(&example_first_party_caveat_different_prefix());

    let matching_verifier = Func(verify_caveat);
    assert!(token.verify(&example_key(), &matching_verifier).is_ok());
    assert!(token.verify(&invalid_key(), &matching_verifier).is_err());
    
    let non_matching_verifier = Func(verify_wrong_value);
    assert!(token.verify(&example_key(), &non_matching_verifier).is_err());
    assert!(token.verify(&invalid_key(), &non_matching_verifier).is_err());

    let multiple_verifier = Func(verify_caveat).link(Func(verify_other));
    assert!(token.verify(&example_key(), &multiple_verifier).is_ok());
}
