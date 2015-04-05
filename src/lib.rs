#![crate_name = "macaroons"]
#![crate_type = "lib"]

#![feature(core)]
#![feature(collections)]
#![feature(convert)]

extern crate sodiumoxide;
extern crate rustc_serialize;

pub mod token;
pub mod caveat;
