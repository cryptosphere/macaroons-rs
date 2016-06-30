pub use token::Token;
pub use caveat::{Caveat, Predicate};

pub type CaveatVerifier = Fn(&Predicate) -> bool;

pub struct Verifier {
    pub matchers: Vec<Box<CaveatVerifier>>,
}

impl Verifier {
    pub fn new(matchers: Vec<Box<CaveatVerifier>>) -> Verifier {
        Verifier { matchers: matchers }
    }
        
    pub fn verify(&self, key: &[u8], token: &Token) -> bool {
        if !token.verify(&key) {
            return false;
        }

        for c in &token.caveats {
            let verified = match c.verification_id {
                None => self.verify_first_party(c),
                _ => self.verify_third_party()
            };
            if verified == false {
                return false;
            }
        }
        true
    }

    fn verify_first_party(&self, c: &Caveat) -> bool {
        let matchers = &self.matchers;
        for m in matchers {
            if m(&Predicate(c.caveat_id.clone())) {
                return true;
            }
        }
        false
    }

    fn verify_third_party(&self) -> bool {
        unimplemented!();
    }
}
