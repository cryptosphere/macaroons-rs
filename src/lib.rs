#![crate_name = "macaroons"]
#![crate_type = "lib"]

extern crate sodiumoxide;

pub mod macaroons {
  pub mod token;
  pub mod caveat;

  pub const KEYBYTES: usize = 32;
  pub const SIGNATUREBYTES: usize = 32;
}
