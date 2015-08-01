#![crate_name = "macaroons"]
#![crate_type = "lib"]

extern crate sodiumoxide;
extern crate rustc_serialize;

pub mod token;
pub mod caveat;
pub mod verifier;
