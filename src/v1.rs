use std;

use rustc_serialize::base64::{self, FromBase64, ToBase64};

use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key, State, TAGBYTES};
use sodiumoxide::crypto::secretbox;

use super::KEY_GENERATOR;
use caveat::{Caveat, Predicate};
use error::{Error, Result};
use token::Token;

const PACKET_PREFIX_LENGTH: usize = 4;
const MAX_PACKET_LENGTH: usize = 65535;

pub struct V1Token {
    pub identifier: Vec<u8>,
    pub location: Option<Vec<u8>>,
    pub caveats: Vec<Caveat>,
    pub tag: [u8; TAGBYTES],
}

struct Packet {
    pub id: Vec<u8>,
    pub value: Vec<u8>,
    pub length: usize,
}

impl V1Token {
    fn packetize(result: &mut Vec<u8>, field: &str, value: &[u8]) -> Result<()> {
        let field_bytes: Vec<u8> = Vec::from(field);
        let packet_length = PACKET_PREFIX_LENGTH + field_bytes.len() + value.len() + 2;

        if packet_length > MAX_PACKET_LENGTH {
            return Err(Error::PacketLength);
        }

        let pkt_line = format!("{:04x}{} ", packet_length, field).into_bytes();
        result.extend(pkt_line.into_iter());
        result.extend(value.clone().into_iter());
        result.push(b'\n');

        Ok(())
    }

    fn depacketize(data: &[u8], index: usize) -> Result<Packet> {
        let length_str = try!(std::str::from_utf8(&data[index..index + PACKET_PREFIX_LENGTH])
            .map_err(|_e| Error::PacketLength));

        let packet_length = try!(usize::from_str_radix(length_str, 16)
            .map_err(|_e| Error::PacketLength));

        let mut packet_bytes = data[index + PACKET_PREFIX_LENGTH..index + packet_length].to_vec();

        let pos = try!(packet_bytes.iter()
            .position(|&byte| byte == b' ')
            .ok_or(Error::MalformedPacket));

        let (id, value_arr) = packet_bytes.split_at_mut(pos);
        let mut value = value_arr.to_vec();
        value.remove(0);

        if try!(value.pop().ok_or(Error::MalformedPacket)) != b'\n' {
            return Err(Error::MalformedPacket);
        }

        Ok(Packet {
            id: id.to_vec(),
            value: value,
            length: packet_length,
        })
    }
}

impl Token for V1Token {
    fn new(key: &[u8], identifier: Vec<u8>, location: Option<Vec<u8>>) -> V1Token {
        let Tag(personalized_key) = hmacsha256::authenticate(&key, &Key(*KEY_GENERATOR));
        let Tag(tag) = hmacsha256::authenticate(&identifier, &Key(personalized_key));

        V1Token {
            location: location,
            identifier: identifier,
            caveats: Vec::new(),
            tag: tag,
        }
    }

    fn deserialize(macaroon: Vec<u8>) -> Result<V1Token> {
        let token_data = try!(macaroon.from_base64().map_err(|_e| Error::Base64));
        let mut index: usize = 0;

        // Parse the (optional location and) identifier packets
        let packet1 = try!(V1Token::depacketize(&token_data, index));
        index += packet1.length;

        let (identifier, location) = match &packet1.id[..] {
            b"identifier" => (packet1.value, None),
            b"location" => {
                let packet2 = try!(V1Token::depacketize(&token_data, index));
                index += packet2.length;

                if &packet2.id[..] != b"identifier" {
                    return Err(Error::MissingIdentifier);
                }

                (packet2.value, Some(packet1.value))
            }
            _ => return Err(Error::MissingIdentifier),
        };

        let mut caveats: Vec<Caveat> = Vec::new();
        let mut tag: Option<[u8; TAGBYTES]> = None;

        // Parse caveats
        while index < token_data.len() {
            let packet = try!(V1Token::depacketize(&token_data, index));

            index += packet.length;

            match &packet.id[..] {
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
                                _ => return Err(Error::PacketOrdering),
                            }

                            caveats.push(Caveat {
                                caveat_id: caveat_id,
                                caveat_key: None,
                                verification_id: verification_id,
                                caveat_location: caveat_location,
                            })
                        }
                        None => return Err(Error::PacketOrdering),
                    }
                }
                b"signature" => {
                    // Make sure signature is the last packet
                    if index != token_data.len() {
                        return Err(Error::PacketOrdering);
                    }

                    if packet.value.len() != TAGBYTES {
                        return Err(Error::SignatureLength);
                    }

                    let mut signature_bytes = [0u8; TAGBYTES];
                    signature_bytes.copy_from_slice(&packet.value);

                    tag = Some(signature_bytes);
                }
                _ => return Err(Error::UnknownPacketType),
            }
        }

        if tag == None {
            return Err(Error::MissingSignature);
        }

        let token = V1Token {
            identifier: identifier,
            location: location,
            caveats: caveats,
            tag: tag.unwrap(),
        };

        Ok(token)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        // TODO: estimate capacity and use Vec::with_capacity
        let mut result: Vec<u8> = Vec::new();

        if self.location.is_some() {
            try!(V1Token::packetize(&mut result, "location", &self.location.clone().unwrap()));
        }

        try!(V1Token::packetize(&mut result, "identifier", &self.identifier));

        for caveat in &self.caveats {
            try!(V1Token::packetize(&mut result, "cid", &caveat.caveat_id));

            if caveat.verification_id.is_some() {
                try!(V1Token::packetize(&mut result,
                                        "vid",
                                        &caveat.verification_id.clone().unwrap()));
            }

            if caveat.caveat_location.is_some() {
                try!(V1Token::packetize(&mut result,
                                        "cl",
                                        &caveat.caveat_location.clone().unwrap()));
            }
        }

        try!(V1Token::packetize(&mut result, "signature", &self.tag.to_vec()));

        Ok(result.to_base64(base64::URL_SAFE).into_bytes())
    }

    fn add_caveat(&self, caveat: &Caveat) -> V1Token {
        let key_bytes = self.tag;
        let mut new_caveats = self.caveats.to_vec();

        let new_tag = match caveat.caveat_key {
            Some(ref key) => {
                let Tag(personalized_key) = hmacsha256::authenticate(&key, &Key(*KEY_GENERATOR));
                let nonce = secretbox::gen_nonce();

                let mut new_caveat = caveat.clone();
                let verification_id =
                    secretbox::seal(&key_bytes,
                                    &nonce,
                                    &secretbox::xsalsa20poly1305::Key(personalized_key));

                let mut caveat_authenticator = State::init(&key_bytes);

                let Tag(caveat_id_tag) = hmacsha256::authenticate(&new_caveat.caveat_id,
                                                                  &Key(key_bytes));
                caveat_authenticator.update(&caveat_id_tag);

                let Tag(verification_id_tag) = hmacsha256::authenticate(&verification_id,
                                                                        &Key(key_bytes));
                caveat_authenticator.update(&verification_id_tag);

                new_caveat.verification_id = Some(verification_id);

                new_caveats.push(new_caveat);
                caveat_authenticator.finalize()
            }
            None => {
                new_caveats.push(caveat.clone());
                hmacsha256::authenticate(&caveat.caveat_id, &Key(key_bytes))
            }
        };

        V1Token {
            identifier: self.identifier.clone(),
            location: self.location.clone(),
            caveats: new_caveats,
            tag: new_tag.0,
        }
    }

    fn verify(&self, key: &[u8]) -> bool {
        let mut verify_token = V1Token::new(&key, self.identifier.clone(), self.location.clone());

        for caveat in &self.caveats {
            verify_token = verify_token.add_caveat(&caveat)
        }

        verify_token.tag == self.tag
    }
}
