#![crate_name = "macaroons"]
#![crate_type = "lib"]

#![feature(collections)]

extern crate sodiumoxide;

pub mod token;
pub mod caveat;
