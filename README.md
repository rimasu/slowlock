[![Rust](https://github.com/rimasu/yatlv/actions/workflows/rust.yml/badge.svg)](https://github.com/rimasu/yatlv/actions/workflows/rust.yml)
[![Docs](https://docs.rs/yatlv/badge.svg)](https://docs.rs/yatlv)

## Slow Lock

Slow is a thin convenience layer that makes it easy to use a proof of work function
to recover a cipher key.

It implements no new cryptographic primitives, instead in provides some mechanisms to

1) Help calibrate the proof of work function to take a reasonable amount of time
2) Detect when a previously configured proof of work function is no-long adequate

Currently the only implementation of the proof of work function is based
on Argon2.


Basic process:

1. `password` is passed through proof of work function to create `cipher_key`.
3. `cipher_key` and `nonce` are used to decrypt/encrypt content.

To be useful the proof of work function must take a reasonable amount of time/effort
to complete. This crates provides a [Argon2WorkFunctionCalibrator] with (I hope) reasonable
defaults that can be used to create work functions with variable target durations.

The other part of this is detecting when a previously reasonable work function is now
completing too quickly. Unless occasionally re-calibrated, we should expect this to happen
over time as machine performance improves.

This crate has X ways to to detect work functions that are too weak.

1) If logging is enabled and the work function completes in less than two thirds the expected
time a warning is logged.

### Design Choices (for review)

This is a log of design choices I have made in this library. I am not a security
expert and these may be wrong - so I'm calling them out here so that users are
pre-warned.  Any review gratefully received.

#### Fixed Argon2 "secret"

Argon2 supports use of a secret.  This can be used a 'pepper'. Unlike a salt, a pepper is
not stored along side the hash and can be reused across multiple passwords. Typically it
is long and may be stored be in some trusted hardware store.  This secret means that an attacker
in possession of the hashed password and salt still has a missing component.

In this library Argon2 is not being used to verify password, but as a proof of work
function. So although the salt is stored, the hashed password is never exposed (it is
directly used as the `cipher_key`). This means there is limited risk of the attacker gaining access
to the `salt` and hashed password.


Current version: 0.1.0

This is a hobby project; I don't have the bandwidth
to properly maintain this.  You are welcome to use
and fork at your risk, but I would not recommend this
crate for any serious work.



License: MIT/Apache-2.0
