[![Rust](https://github.com/rimasu/slowlock/actions/workflows/rust.yml/badge.svg)](https://github.com/rimasu/slowlock/actions/workflows/rust.yml)
[![Docs](https://docs.rs/slowlock/badge.svg)](https://docs.rs/slowlock)

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

#### Trustworthy Work Function

Currently the `password` is passed to the proof of work function and the output of
the proof of work function is used as the `cipher_key`.

So as well as being a proof of work function, it is also performing any necessary
key widening.  It would seem cleaner to separate these responsibilities. Decoupling
would, of course, introduce its own complexity.  Given the current proof of
work function is explicitly designed with key-widening in mind this complexity
has been avoided.

If better separation of real value (feed-back welcome) an alternative approach would be:

1) Pass hash of `password` to proof of work function
2) Combine proof of work output with original `password` to make `cipher_key`.

This would prevent leakages in the proof of work function revealing either the `password`
or the `cipher_key`.  To do this I would need some way of safely performing step 2.
I assume that for a 256 bit cipher, combining the `password` and proof of work using `SHA-256`
would be acceptable.  I don't currently see a nice way to make this work on range
of cipher-key lengths.

#### Secret Hygiene

The crate handles two secrets, the original `password` and the `cipher_key`. If either of
these leaked then the security of the cipher is compromised.  These are a ways I am aware they
could leak:

1) Logging (easily avoided).
2) Memory being released without being cleared.
3) Memory being written to persistent storage.

This crate only handles the `password` as a reference `&[u8]`. As mentioned it is passed to
the proof of work function. As the current proof of work function has been developed for
password hashes I am assuming that it has taken reasonable precautions, but am not in a
position to guarantee this.

The `cipher_key` is a little more problematic. The proof of work function returns
the result wrapped as a SecretVec to ensure that the `cipher_key` is cleared before
the memory is released.

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
