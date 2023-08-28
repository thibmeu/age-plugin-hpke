# age-plugin-hpke: HPKE plugin for age

[![Documentation](https://img.shields.io/badge/docs-main-blue.svg)][Documentation]
![License](https://img.shields.io/crates/l/age-plugin-hpke.svg)
[![crates.io](https://img.shields.io/crates/v/age-plugin-hpke.svg)][Crates.io]

[Crates.io]: https://crates.io/crates/age-plugin-hpke
[Documentation]: https://docs.rs/age-plugin-hpke/

age-plugin-hpke is a plugin for [age](https://github.com/C2SP/C2SP/blob/main/age.md). It provides an age Identity and Recipient consuming Hybrid Public Key Encrypted (HPKE) files.

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

Read [age installation instructions](https://github.com/FiloSottile/age#installation) to install age.

## Usage

You can use the `--help` option to get more details about the command and its options.

```bash
age-plugin-hpke [OPTIONS]
```

### Generate recipient and identity

Create an identity using Kyber768.

```shell
age-plugin-hpke --generate --kem x25519-kyber768-draft00 --aead cha-cha20-poly1305 --associated-data "user@example.com" > my_id.key
```

For convenience, you can also create an associated recipient

```shell
cat my_id.key | grep 'recipient' | sed 's/.*\(age1.*\)/\1/' > my_id.key.pub
```

> The recipient and identity size are going to vary based on the KEM. With Post-quantum, keys are large.

### HPKE Encryption

Encrypt `Hello age-plugin-hpke!` string with your new key.

```shell
echo "Hello age-plugin-hpke!" | age -a -R my_id.key.pub > data.age
age --decrypt -i my_id.key data.age
Hello age-plugin-hpke!
```

## Security Considerations

This software has not been audited. Please use at your sole discretion. With this in mind, age-plugin-hpke security relies on the following:

* [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) by R. Barnes, K. Bhargavan, B. Lipp, C. Wood, and its implementation in [rozbb/rust-hpke](https://github.com/rozbb/rust-hpke),
* [age](https://github.com/C2SP/C2SP/blob/main/age.md) encryption protocol, and its implementation in [str4d/rage](https://github.com/str4d/rage),

## FAQ

## age format

### Stanza

`hpke <KEM> <AEAD> <ASSOCIATED_DATA>`

### Recipient

`age1hpke1<KEM_ALG><AEAD_ALG><KDF_ALG><PUBLIC_KEY><ASSOCIATED_DATA>`

### Identity

`AGE-PLUGIN-HPKE-<KEM_ALG><AEAD_ALG><KDF_ALG><PRIVATE_KEY><ASSOCIATED_DATA>`

### Why age for HPKE

Why not? At the time of writting, age is available on multiple platform, has a file format allowing for agility, and a decent tooling to integrate with.

IETF format with [HPKE in COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/) might offer an alternative path down the line.

### Usage as a library

The underlying primitive used in the cli are exposed via a library. This includes the age stanza, recipient, and identity, as well as tools to generate an identity from scratch.

```shell
cargo add age-plugin-hpke
```

## License

This project is under the MIT license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be MIT licensed as above, without any additional terms or conditions.
