[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/did-go/main/LICENSE)
[![Release](https://img.shields.io/github/release/trustbloc/did-go.svg?style=flat-square)](https://github.com/trustbloc/did-go/releases/latest)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/did-go)

[![Build Status](https://github.com/trustbloc/did-go/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/trustbloc/did-go/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/did-go)](https://goreportcard.com/report/github.com/trustbloc/did-go)


# TrustBloc Decentralized Identifier (DID) Go Library

The TrustBloc DID Go repo contains core [W3C Decentralized Identifier (DID)](https://www.w3.org/TR/did-core/) related shared code.

The library has the following implementations.
- [W3C Decentralized Identifier (DID)](https://www.w3.org/TR/did-core/) Data model
- DID Method client implementation
  - [DID Web](https://w3c-ccg.github.io/did-method-web/)
  - [DID Key](https://w3c-ccg.github.io/did-method-key/)
  - [DID JWK](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
  - [DID Sidetree longform](https://identity.foundation/sidetree/spec/)
  - [DID HTTP Resolver](https://w3c-ccg.github.io/did-resolution/)
- JSON-LD wrappers built on top of [piprate/json-gold](https://github.com/piprate/json-gold) along with signer and verifier implementation


## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
