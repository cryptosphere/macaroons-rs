#![crate_name = "macaroons"]
#![crate_type = "lib"]

extern crate sodiumoxide;
extern crate rustc_serialize;

pub mod v1 {
    pub mod token;
}

pub mod caveat;
pub mod verifier;

// Macaroons personalize the HMAC key using the string
// "macaroons-key-generator" padded to 32-bytes with zeroes
pub const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";
