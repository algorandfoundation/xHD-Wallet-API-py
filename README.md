# xHD-Wallet-API

Python library for BIP32-Ed25519 hierarchical deterministic key derivation. This library supports two schemes:

- `V2`, which is the scheme defined by Khovratovich and Law in [BIP32-Ed25519: Hierarchical Deterministic Keys over a Non-linear Keyspace](https://ieeexplore.ieee.org/document/7966967)
- `Peikert`, which is [Chris Peikert's adendum](https://github.com/algorandfoundation/bip32-ed25519-addendum/) to the Khovratovich and Law scheme that results in more entropy to derived keys.

All the core functionality is implement in Rust and exposed to Python via a C API. The repo for the Rust library is: https://github.com/algorandfoundation/xHD-Wallet-API-rs
