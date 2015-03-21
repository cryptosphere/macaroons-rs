#![crate_name = "macaroons"]
#![crate_type = "lib"]

#![feature(core)]
#![feature(collections)]

extern crate sodiumoxide;
extern crate "rustc-serialize" as serialize;

pub mod token;
pub mod caveat;
