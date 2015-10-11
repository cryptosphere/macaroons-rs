pub use token::Token;
pub use caveat::{Caveat, Predicate};

pub struct Verifier<F> {
  pub matcher: F
}

impl<F> Verifier<F> where F: Fn(&Predicate) -> bool {
  pub fn new(matcher: F) -> Verifier<F> {
    Verifier {
      matcher: matcher
    }
  }

  pub fn verify(&self, key: &Vec<u8>, token: &Token) -> bool {
    if !token.verify(&key) {
      return false;
    }

    let matcher = &self.matcher;
    token.caveats.iter().all(|caveat| { matcher(&Predicate(caveat.caveat_id.clone())) })
  }
}
