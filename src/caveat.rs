pub struct Caveat {
  pub caveat_id:       Vec<u8>,
  pub verification_id: Option<Vec<u8>>,
  pub caveat_location: Option<Vec<u8>>
}

impl Caveat {
  pub fn new(predicate: Vec<u8>) -> Caveat {
    Caveat {
      caveat_id:       predicate,
      verification_id: None,
      caveat_location: None
    }
  }
}
