use std::marker::Sized;

use caveat::Caveat;

pub trait Token {
    fn new(key: &[u8], identifier: Vec<u8>, location: Option<Vec<u8>>) -> Self;
    fn deserialize(macaroon: Vec<u8>) -> Result<Self, &'static str> where Self: Sized;
    fn add_caveat(&self, caveat: &Caveat) -> Self;
    fn verify(&self, key: &[u8]) -> bool;
    fn serialize(&self) -> Vec<u8>;
}
