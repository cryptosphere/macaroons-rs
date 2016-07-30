Macaroons for Rust
==================
[![Build Status](https://travis-ci.org/cryptosphere/rust-macaroons.svg?branch=master)](https://travis-ci.org/cryptosphere/rust-macaroons)
[![Latest Version](https://img.shields.io/crates/v/macaroons.svg)](https://crates.io/crates/macaroons)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cryptosphere/rust-macaroons/blob/master/LICENSE)

A better kind of cookie.

Macaroons are a bearer credential format built around "caveats", i.e. conditions
that must hold for a particular credential to be authorized. Using neat crypto
tricks, anyone holding a Macaroon can add more caveats to a Macaroon, but once
caveats are added they cannot be removed.

http://macaroons.io

### Is it any good?

[Yes.](http://news.ycombinator.com/item?id=3067434)

### Is it "Production Ready™"?

The library is ready for eager early adopters. If you're using Rust, you're
probably one of those anyway.

The following features have been implemented:

* Creating Macaroons
* Verifying Macaroons
* First-party caveats
* Third-party caveats
* Serializing to base64url-encoded binary format
* Deserializing base64url-encoded Macaroons
* Verifying first-party caveats

The following features still need to be implemented:

* Discharge macaroons
* Verifying third-party caveats

Additional planned work:

* Nom-based parser (may require API changes)

## V2 Format Support

[The Macaroons format is changing!](https://groups.google.com/forum/#!msg/macaroons/EIDUZQoelq8/KnbVukmGBQAJ)

A specification for a new, more compact "V2" format has been published.

This library has begun to implement it. In the process, the API is changing
so that it can support both the old and new formats.

Pardon our dust.

## Help and Discussion

Interested in Macaroons? Join the Macaroons Google Group:

https://groups.google.com/forum/#!forum/macaroons

You can also join by email by sending an email message here:

[macaroons+subscribe@googlegroups.com](mailto:macaroons+subscribe@googlegroups.com)

We're also on IRC at #macaroons on irc.freenode.net.

## Usage

Coming soon!

## Additional Reading

* [Macaroons: Cookies with Contextual Caveats for Decentralized Authroization in the Cloud](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/41892.pdf)

## License

Copyright (c) 2015-2016 Tony Arcieri. Distributed under the MIT License.
See LICENSE.txt for further details.
