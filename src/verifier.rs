use caveat::{Caveat, Predicate};
use error::{Result, Error};
use token::Token;
use v1::V1Token;

pub type CaveatVerifier = Fn(&Predicate) -> bool;

pub struct Verifier {
    pub matchers: Vec<Box<CaveatVerifier>>,
}

impl Verifier {
    pub fn new(matchers: Vec<Box<CaveatVerifier>>) -> Verifier {
        Verifier { matchers: matchers }
    }

    pub fn verify(&self, key: &[u8], token: &V1Token) -> Result<()> {
        try!(token.verify(&key));

        for c in &token.caveats {
            if c.verification_id == None {
                try!(self.verify_first_party(c));
            } else {
                try!(self.verify_third_party());
            }
        }

        Ok(())
    }

    fn verify_first_party(&self, c: &Caveat) -> Result<()> {
        let matchers = &self.matchers;
        for m in matchers {
            if m(&Predicate(c.caveat_id.clone())) {
                return Ok(());
            }
        }
        
        Err(Error::FirstPartyCaveatFailed)
    }

    fn verify_third_party(&self) -> Result<()> {
        unimplemented!();
    }
}
