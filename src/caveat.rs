#[derive(Clone)]
pub struct Predicate(pub Vec<u8>);

#[derive(Clone)]
pub struct Caveat {
  pub predicate: Predicate
}

impl Caveat {
  pub fn new(predicate: Predicate) -> Caveat {
    Caveat {
      predicate: predicate
    }
  }
}
