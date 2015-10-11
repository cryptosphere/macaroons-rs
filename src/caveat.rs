#[derive(Clone)]
pub struct Predicate(pub Vec<u8>);

#[derive(Clone)]
pub struct Caveat {
  pub caveat_id:       Vec<u8>,
  pub caveat_key:      Option<Vec<u8>>,
  pub verification_id: Option<Vec<u8>>,
  pub caveat_location: Option<Vec<u8>>
}

impl Caveat {
  pub fn first_party(predicate: Predicate) -> Caveat {
    let Predicate(caveat_id) = predicate;

    Caveat {
      caveat_id:       caveat_id,
      caveat_key:      None,
      verification_id: None,
      caveat_location: None
    }
  }

  pub fn third_party(
    caveat_key:      Vec<u8>,
    caveat_id:       Vec<u8>,
    caveat_location: Vec<u8>
  ) -> Caveat {
    Caveat {
      caveat_id:       caveat_id,
      caveat_key:      Some(caveat_key),
      verification_id: None,
      caveat_location: Some(caveat_location)
    }
  }
}
