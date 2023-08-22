# age-plugin-hpke: HPKE plugin for age

[![Documentation](https://img.shields.io/badge/docs-main-blue.svg)][Documentation]
![License](https://img.shields.io/crates/l/age-plugin-hpke.svg)
[![crates.io](https://img.shields.io/crates/v/age-plugin-hpke.svg)][Crates.io]

[Crates.io]: https://crates.io/crates/age-plugin-hpke
[Documentation]: https://docs.rs/age-plugin-hpke/

age-plugin-tlock is a plugin for [age](https://github.com/C2SP/C2SP/blob/main/age.md). It provides an age Identity and Recipient consuming Hybrid Public Key Encrypted (HPKE) files.

HPKE is defined in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), and age-plugin are defined by [C2SP](https://github.com/C2SP/C2SP/blob/main/age.md).

## Tables of Content

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Security Considerations](#security-considerations)
* [FAQ](#faq)
* [License](#license)

## Features

* HPKE recipienties and identities
* Post Quantum HPKE with Kyber Draft00
* Plugin cli for age
* Plugin library for age
* Cross platform (Linux, Windows, macOS)

## What's next

* Agree on age format

## Installation

| Environment        | CLI Command               |
|:-------------------|:--------------------------|
| Cargo (Rust 1.67+) | `cargo install --git https://github.com/thibmeu/age-plugin-hpke` |

## Usage

Not implemented.

## Security Considerations

This software has not been audited. Please use at your sole discretion. With this in mind, dee security relies on the following:
* [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) by R. Barnes, K. Bhargavan, B. Lipp, C. Wood, and its implementation in [rozbb/rust-hpke](https://github.com/rozbb/rust-hpke),
* [age](https://github.com/C2SP/C2SP/blob/main/age.md) encryption protocol, and its implementation in [str4d/rage](https://github.com/str4d/rage),

## FAQ

## age format

### Stanza

`hpke <KEM> <AEAD> <AHDH>`

### Recipient

`age1hpke1<PUBLIC_KEY>`

### Identity

`AGE-PLUGIN-HPKE-<PRIVATE_KEY>`

### Why age for HPKE

Why not? At the time of writting, age is available on multiple platform, has a file format allowing for agility, and a decent tooling to integrate with.

IETF format with [HPKE in COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/) might offer an alternative path down the line.

## License

This project is under the MIT license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be MIT licensed as above, without any additional terms or conditions.
