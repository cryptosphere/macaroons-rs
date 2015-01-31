Macaroons
=========
[![Build Status](https://travis-ci.org/cryptosphere/rust-macaroons.svg?branch=master)](https://travis-ci.org/cryptosphere/rust-macaroons)

Macaroons Are Better Than Cookies!

Macaroons are a bearer credential format built around "caveats", i.e. conditions
that must hold for a particular credential to be authorized. Using neat crypto
tricks, anyone holding a Macaroon can add more caveats to a Macaroon, but once
caveats are added they cannot be removed.
