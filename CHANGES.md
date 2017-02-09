## 0.3.3 (2017-02-08)

* Update project links to use "macaroons-rs"

## 0.3.2 (2017-01-31)

* Add "authentication" category to Cargo.toml.

## 0.3.1 (2016-07-31)

* [#15](https://github.com/cryptosphere/macaroons-rs/pull/15)
  Get rid of Predicate tuple struct.
  ([@tarcieri])

## 0.3.0 (2016-07-31)

* [#14](https://github.com/cryptosphere/macaroons-rs/pull/14)
  Return Results for verification (instead of bool).
  ([@tarcieri])

* [#13](https://github.com/cryptosphere/macaroons-rs/pull/13)
  Return errors for out-of-order V1 packets.
  ([@tarcieri])

* [#12](https://github.com/cryptosphere/macaroons-rs/pull/12)
  Error type.
  ([@tarcieri])

* [#10](https://github.com/cryptosphere/macaroons-rs/pull/10)
  Token trait.
  ([@tarcieri])

* [#8](https://github.com/cryptosphere/macaroons-rs/pull/8)
  Namespace Token as v1::V1Token.
  ([@tarcieri])

* [#6](https://github.com/cryptosphere/macaroons-rs/pull/6)
  Use &[u8] instead of &Vec<u8>.
  ([@panicbit])

* [#5](https://github.com/cryptosphere/macaroons-rs/pull/5)
  Make locations an Option.
  ([@tarcieri])

* [#3](https://github.com/cryptosphere/macaroons-rs/pull/3)
  Initial verifier type.
  ([@ecordell])

## 0.2.1 (2015-11-05)

* Utilize sodiumoxide IUF HMAC API

## 0.2.0 (2015-10-13)

* Initial serialization-only support for third-party caveats (no verification)

## 0.1.1 (2015-07-19)

* Support for verifying Tokens against keys

## 0.1.0 (2015-05-18)

* Initial release

[@tarcieri]: https://github.com/tarcieri
[@ecordell]: https://github.com/ecordell
[@panicbit]: https://github.com/panicbit
