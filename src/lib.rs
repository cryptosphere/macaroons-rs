#![crate_name = "macaroons"]
#![crate_type = "lib"]

extern crate sodiumoxide;

pub mod macaroons {
  pub mod token;
  pub mod caveat;
}
