
use std::marker::Sized;

use caveat::Caveat;
use error::Result;

pub trait Token {
    fn new(key: &[u8], identifier: Vec<u8>, location: Option<Vec<u8>>) -> Self;
    fn deserialize(macaroon: Vec<u8>) -> Result<Self> where Self: Sized;
    fn serialize(&self) -> Result<Vec<u8>>;
    fn add_caveat(&self, caveat: &Caveat) -> Self;
    fn verify(&self, key: &[u8]) -> bool;
}
