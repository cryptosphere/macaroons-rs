use std;

pub use caveat::{Caveat, Predicate};

use rustc_serialize::base64::{self, FromBase64, ToBase64};

pub use sodiumoxide::crypto::auth::hmacsha256::Tag;
use sodiumoxide::crypto::auth::hmacsha256::{Key, State, TAGBYTES};
use sodiumoxide::crypto::auth::hmacsha256::authenticate;
use sodiumoxide::crypto::secretbox;

use KEY_GENERATOR;

const PACKET_PREFIX_LENGTH: usize = 4;
const MAX_PACKET_LENGTH: usize = 65535;

pub struct Token {
    pub location: Option<Vec<u8>>,
    pub identifier: Vec<u8>,
    pub caveats: Vec<Caveat>,
    pub tag: Tag,
}

struct Packet {
    pub id: Vec<u8>,
    pub value: Vec<u8>,
    pub length: usize,
}

impl Token {
    pub fn new(key: &[u8], identifier: Vec<u8>, location: Option<Vec<u8>>) -> Token {
        let Tag(personalized_key) = authenticate(&key, &Key(*KEY_GENERATOR));
        let tag = authenticate(&identifier, &Key(personalized_key));

        Token {
            location: location,
            identifier: identifier,
            caveats: Vec::new(),
            tag: tag,
        }
    }

    pub fn deserialize(macaroon: Vec<u8>) -> Result<Token, &'static str> {
        let mut location: Option<Vec<u8>> = None;
        let mut identifier: Option<Vec<u8>> = None;
        let mut caveats: Vec<Caveat> = Vec::new();
        let mut tag: Option<Tag> = None;

        let token_data = match macaroon.from_base64() {
            Ok(bytes) => bytes,
            _ => return Err("couldn't parse base64"),
        };

        let mut index: usize = 0;

        while index < token_data.len() {
            let packet = match Token::depacketize(&token_data, index) {
                Ok(p) => p,
                Err(reason) => return Err(reason),
            };

            index += packet.length;

            match &packet.id[..] {
                b"location" => location = Some(packet.value),
                b"identifier" => identifier = Some(packet.value),
                b"cid" => caveats.push(Caveat::first_party(Predicate(packet.value))),
                b"vid" | b"cl" => {
                    match caveats.pop() {
                        Some(caveat) => {
                            let caveat_id = caveat.caveat_id;
                            let mut verification_id = caveat.verification_id;
                            let mut caveat_location = caveat.caveat_location;

                            match &packet.id[..] {
                                b"vid" => verification_id = Some(packet.value),
                                b"cl" => caveat_location = Some(packet.value),
                                _ => (),
                            }

                            caveats.push(Caveat {
                                caveat_id: caveat_id,
                                caveat_key: None,
                                verification_id: verification_id,
                                caveat_location: caveat_location,
                            })
                        }
                        None => return Err("invalid third party caveat field ordering"),
                    }
                }
                b"signature" => {
                    if packet.value.len() != TAGBYTES {
                        return Err("invalid signature length");
                    }

                    let mut signature_bytes = [0u8; TAGBYTES];
                    for (src, dst) in packet.value.iter().zip(signature_bytes.iter_mut()) {
                        *dst = *src;
                    }

                    tag = Some(Tag(signature_bytes))
                }
                _ => return Err("unrecognized packet type"),
            }
        }

        if identifier == None {
            return Err("no 'identifier' found");
        }
        if tag == None {
            return Err("no 'signature' found");
        }

        let token = Token {
            location: location,
            identifier: identifier.unwrap(),
            caveats: caveats,
            tag: tag.unwrap(),
        };

        Ok(token)
    }

    fn depacketize(data: &[u8], index: usize) -> Result<Packet, &'static str> {
        // TODO: parse this length without involving any UTF-8 conversions
        let length_str = match std::str::from_utf8(&data[index..index + PACKET_PREFIX_LENGTH]) {
            Ok(string) => string,
            _ => return Err("couldn't stringify packet length"),
        };

        let packet_length: usize = match i16::from_str_radix(length_str, 16) {
            Ok(length) => length as usize,
            _ => return Err("couldn't parse packet length"),
        };

        let mut packet_bytes = data[index + PACKET_PREFIX_LENGTH..index + packet_length].to_vec();

        let pos = match packet_bytes.iter().position(|&byte| byte == b' ') {
            Some(i) => i,
            None => return Err("malformed packet"),
        };

        let (id, value_arr) = packet_bytes.split_at_mut(pos);
        let mut value = value_arr.to_vec();
        value.remove(0);

        match value.pop().unwrap() {
            b'\n' => (),
            _ => return Err("packet not newline terminated"),
        }

        Ok(Packet {
            id: id.to_vec(),
            value: value,
            length: packet_length,
        })
    }

    pub fn add_caveat(&self, caveat: &Caveat) -> Token {
        let Tag(key_bytes) = self.tag;
        let mut new_caveats = self.caveats.to_vec();

        let new_tag = match caveat.caveat_key {
            Some(ref key) => {
                let Tag(personalized_key) = authenticate(&key, &Key(*KEY_GENERATOR));
                let nonce = secretbox::gen_nonce();

                let mut new_caveat = caveat.clone();
                let verification_id =
                    secretbox::seal(&key_bytes,
                                    &nonce,
                                    &secretbox::xsalsa20poly1305::Key(personalized_key));

                let mut caveat_authenticator = State::init(&key_bytes);

                let Tag(caveat_id_tag) = authenticate(&new_caveat.caveat_id, &Key(key_bytes));
                caveat_authenticator.update(&caveat_id_tag);

                let Tag(verification_id_tag) = authenticate(&verification_id, &Key(key_bytes));
                caveat_authenticator.update(&verification_id_tag);

                new_caveat.verification_id = Some(verification_id);

                new_caveats.push(new_caveat);
                caveat_authenticator.finalize()
            }
            None => {
                new_caveats.push(caveat.clone());
                authenticate(&caveat.caveat_id, &Key(key_bytes))
            }
        };

        Token {
            identifier: self.identifier.clone(),
            location: self.location.clone(),
            caveats: new_caveats,
            tag: new_tag,
        }
    }

    pub fn verify(&self, key: &[u8]) -> bool {
        let mut verify_token = Token::new(&key, self.identifier.clone(), self.location.clone());

        for caveat in &self.caveats {
            verify_token = verify_token.add_caveat(&caveat)
        }

        verify_token.tag == self.tag
    }

    pub fn serialize(&self) -> Vec<u8> {
        // TODO: estimate capacity and use Vec::with_capacity
        let mut result: Vec<u8> = Vec::new();

        match self.location.clone() {
            Some(location) => Token::packetize(&mut result, "location", &location),
            None => (),
        }

        Token::packetize(&mut result, "identifier", &self.identifier);

        for caveat in self.caveats.iter() {
            Token::packetize(&mut result, "cid", &caveat.caveat_id);

            match caveat.verification_id.clone() {
                Some(vid) => Token::packetize(&mut result, "vid", &vid),
                None => (),
            }

            match caveat.caveat_location.clone() {
                Some(cl) => Token::packetize(&mut result, "cl", &cl),
                None => (),
            }
        }

        let Tag(signature) = self.tag;
        Token::packetize(&mut result, "signature", &signature.to_vec());

        result.to_base64(base64::URL_SAFE).into_bytes()
    }

    fn packetize(result: &mut Vec<u8>, field: &str, value: &[u8]) {
        let field_bytes: Vec<u8> = Vec::from(field);
        let packet_length = PACKET_PREFIX_LENGTH + field_bytes.len() + value.len() + 2;

        if packet_length > MAX_PACKET_LENGTH {
            panic!("packet too large to serialize");
        }

        let pkt_line = format!("{:04x}{} ", packet_length, field).into_bytes();
        result.extend(pkt_line.into_iter());
        result.extend(value.clone().into_iter());
        result.push(b'\n');
    }
}
