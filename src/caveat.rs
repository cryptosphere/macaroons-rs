use std::fmt;

pub type Predicate = Vec<u8>;

#[derive(Clone)]
pub struct Caveat {
    pub caveat_id: Vec<u8>,
    pub caveat_key: Option<Vec<u8>>,
    pub verification_id: Option<Vec<u8>>,
    pub caveat_location: Option<Vec<u8>>,
}

impl Caveat {
    pub fn first_party(caveat_id: Predicate) -> Caveat {
        Caveat {
            caveat_id: caveat_id,
            caveat_key: None,
            verification_id: None,
            caveat_location: None,
        }
    }

    pub fn third_party(caveat_key: Vec<u8>,
                       caveat_id: Vec<u8>,
                       caveat_location: Vec<u8>)
                       -> Caveat {
        Caveat {
            caveat_id: caveat_id,
            caveat_key: Some(caveat_key),
            verification_id: None,
            caveat_location: Some(caveat_location),
        }
    }
}

impl fmt::Display for Caveat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let caveat_id = String::from_utf8(self.caveat_id.clone()).unwrap();
        write!(f, "{}", &caveat_id)
    }
}
