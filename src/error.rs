use std::{fmt, result};
use std::error::Error as StdError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Error {
    Base64,
    PacketLength,
    SignatureLength,
    MalformedPacket,
    PacketOrdering,
    UnknownPacketType,
    MissingIdentifier,
    MissingSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Base64 => "unable to decode Base64",
            Error::PacketLength => "unable to decode packet length, or packet too long",
            Error::SignatureLength => "signature length incorrect",
            Error::MalformedPacket => "packet not properly structured",
            Error::PacketOrdering => "packet types are not in the right order",
            Error::UnknownPacketType => "packet found with unknown type",
            Error::MissingIdentifier => "no 'identifier' found at beginning of token",
            Error::MissingSignature => "no 'signature' found in token",
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
