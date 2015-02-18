#![crate_name = "macaroons"]
#![crate_type = "lib"]

pub mod macaroons {
  pub mod builder;
  pub mod token;
  pub mod caveat;

  pub const KEYBYTES: usize = 32;
  pub const SIGNATUREBYTES: usize = 32;
}
