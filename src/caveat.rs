pub use token::Token;

pub use sodiumoxide::crypto::auth::hmacsha256::{Key, Tag};
use sodiumoxide::crypto::auth::hmacsha256::authenticate;

#[derive(Clone)]
pub struct Predicate(pub Vec<u8>);

#[derive(Clone)]
pub struct Caveat {
  pub predicate:       Predicate,
  pub verification_id: Option<Vec<u8>>,
  pub location:        Option<Vec<u8>>
}

impl Caveat {
  pub fn first_party(predicate: Predicate) -> Caveat {
    Caveat {
      predicate:       predicate,
      verification_id: None,
      location:        None
    }
  }

  pub fn append(self, token: &Token) -> Token {
    let Tag(key_bytes) = token.tag;
    let Predicate(predicate_bytes) = self.predicate.clone();
    let tag = authenticate(&predicate_bytes, &Key(key_bytes));

    let mut new_caveats = token.caveats.to_vec();
    new_caveats.push(self);

    Token {
      identifier: token.identifier.clone(),
      location:   token.location.clone(),
      caveats:    new_caveats,
      tag:        tag
    }
  }
}
