Macaroons for Rust
==================
[![Build Status](https://travis-ci.org/cryptosphere/rust-macaroons.svg?branch=master)](https://travis-ci.org/cryptosphere/rust-macaroons)
[![Latest Version](https://img.shields.io/crates/v/macaroons.svg)](https://crates.io/crates/macaroons)

Macaroons Are Better Than Cookies!

Macaroons are a bearer credential format built around "caveats", i.e. conditions
that must hold for a particular credential to be authorized. Using neat crypto
tricks, anyone holding a Macaroon can add more caveats to a Macaroon, but once
caveats are added they cannot be removed.

http://macaroons.io

### Is it any good?

[Yes.](http://news.ycombinator.com/item?id=3067434)

### Is it "Production Ready™"?

![DANGER: EXPERIMENTAL](https://raw.github.com/cryptosphere/cryptosphere/master/images/experimental.png)

No. This library only implements part of the Macaroons token format, and the API
is changing rapidly.

The following features have been implemented:

* Creating Macaroons
* Verifying Macaroons
* First-party caveats
* Serializing to base64url-encoded binary format
* Deserializing base64url-encoded Macaroons

The following features need to be implemented for this library to be useful:

* Third-party caveats
* Predicate verifiers

## Help and Discussion

Interested in Macaroons? Join the Macaroons Google Group:

https://groups.google.com/forum/#!forum/macaroons

You can also join by email by sending an email message here:

[macaroons+subscribe@googlegroups.com](mailto:macaroons+subscribe@googlegroups.com)

We're also on IRC at #cryptosphere on irc.freenode.net.

## Usage

Coming soon!

Additional Reading
------------------

* [Macaroons: Cookies with Contextual Caveats for Decentralized Authroization in the Cloud](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/41892.pdf)
