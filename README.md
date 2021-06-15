[![Rust](https://github.com/rimasu/slowlock/actions/workflows/rust.yml/badge.svg)](https://github.com/rimasu/slowlock/actions/workflows/rust.yml)
[![Docs](https://docs.rs/slowlock/badge.svg)](https://docs.rs/slowlock)

## Slow Lock

Slow is a thin convenience layer that makes it easy to use a proof of work function
to derive a cipher key.

It implements no new cryptographic primitives, instead in provides some mechanisms to

1) Help calibrate the proof of work function to take a reasonable amount of time
2) Detect when a previously configured proof of work function is no-long adequate

Currently the only implementation of the proof of work function is based
on Argon2.


Basic process:

1. `password` is passed through proof of work function to create `cipher_key`.
3. `cipher_key` and `nonce` are used to decrypt/encrypt content.

To be useful, the proof of work function must take a reasonable amount of time/effort
to complete. This crates provides a [Argon2WorkFunctionCalibrator] that can be used to
create work functions with variable target durations.

Machine performance improves year on year, so we need to occasionally recalibrate
the work function to ensure it continues to present an adequate challenge.  This crate
does not automatically change the work function.  Instead, it measures its duration
and provides a mechanism to alert the calling code when the proof of work function
completes too quickly. These are controlled by the [WorkPolicy]. There are currently
two ways the work policy can alert the user if a proof of work function completes too
quickly:

1) If the `log_warning` policy is enabled, a message is written to the logs
2) If the `return_error` policy is enabled, an error is returned

Both `log_warning` and `return_error` are enabled by default. The exact trigger
levels can be tuned as percentage of the target duration.

Separately, if the proof of work function is calibrated in debug mode, a warning is
generated as the parameters will be far to weak.

### Basic Usage
```rust
use slowlock::{WorkPolicyBuilder, Argon2WorkFunctionCalibrator, NewSlowAead};
use std::time::Duration;
use hex_literal::hex;
use aes_gcm::Aes256Gcm;
use aead::Aead;
use aead::generic_array::GenericArray;

let target_duration = Duration::from_millis(2500);

// Create a policy with a target duration of 2.5s that will:
//  * log a warning if the proof of work function takes less than 75% of the target duration
//  * return an error if the proof of work function takes less than 30% of target duration.
let policy = WorkPolicyBuilder::default()
                .build(target_duration);

// Try to create a lock that uses approximately 5% of total memory and takes
// about 2.5s to process
let work_fn = Argon2WorkFunctionCalibrator::default()
          .calibrate(target_duration)?;

// User supplied secret. This could be a password or a key recovered
// from an earlier stage in the decryption/encryption process.
let password = "super secret password".as_bytes();

// Salt should be generated using a cryptographically secure pseudo-random number generator
// It needs to be stored alongside the encrypted values
let salt = hex!("8a248444f2fc50308a856b35de67b312a4c4be1d180f49e101bf6330af5d47");

// Attempt to create the cipher algorithm using the work function and checking the
// policy.
// This process should take about 2.5 seconds.
let algo: Aes256Gcm = work_fn.slow_new(&password, &salt, &policy)?;


// Nonce _must_ be unique each time data is encrypted with the same cipher_key.
// If the salt if changed the cipher_key is implicitly changed so the nonce
// could be reset.
let nonce = hex!("1d180f49e101bf6330af5d47");

let plain_text = "secret content to protect".as_bytes();

let cipher_text = algo.encrypt(
     GenericArray::from_slice(&nonce),
     plain_text
)?;

let recovered_plain_text = algo.decrypt(
    GenericArray::from_slice(&nonce),
    cipher_text.as_slice()
)?;

assert_eq!(plain_text, recovered_plain_text);

```

### Creating Key Directly

Rather than immediately turning the derived key into a cipher, the caller
directly obtain the key.  This may be useful if the caller wants to cache
the key for later reuse (to avoid having to derive it repeatedly).  Obviously,
the caller must take care that the derived key is not leaked.

```rust
use slowlock::{WorkPolicyBuilder, Argon2WorkFunctionCalibrator};
use std::time::Duration;
use hex_literal::hex;;

let target_duration = Duration::from_millis(2500);

// Create a policy with a target duration of 2.5s that will:
//  * log a warning if the proof of work function takes less than 75% of the target duration
//  * return an error if the proof of work function takes less than 30% of target duration.
let policy = WorkPolicyBuilder::default()
                .build(target_duration);

// Try to create a lock that uses approximately 5% of total memory and takes
// about 2.5s to process
let work_fn = Argon2WorkFunctionCalibrator::default()
          .calibrate(target_duration)?;

// User supplied secret. This could be a password or a key derived
// from an earlier stage in the decryption/encryption process.
let password = "super secret password".as_bytes();

// Salt should be generated using a cryptographically secure pseudo-random number generator
// It needs to be stored alongside the encrypted values
let salt = hex!("8a248444f2fc50308a856b35de67b312a4c4be1d180f49e101bf6330af5d47");

// Attempt to derive the key.
// This process should take about 2.5 seconds.
let key = policy.make_cipher_key(32, &password, &salt, &work_fn)?;

// Can then use key to initialize cipher as many times as needed.

```

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

If better separation of is real value (feed-back welcome) an alternative approach would be:

1) Pass hash of `password` to proof of work function
2) Combine proof of work output with original `password` to make `cipher_key`.

This would prevent leakages in the proof of work function revealing either the `password`
or the `cipher_key`.  To do this I would need some way of safely performing step 2.
I assume that for a 256 bit cipher, combining the `password` and proof of work using `SHA-256`
would be acceptable.  I don't currently see a nice way to make this work on range
of cipher-key lengths. A review of <https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml>
suggest that  128 and 256 are by far the most common key lengths.

#### Secret Hygiene

The crate handles two secrets, the original `password` and the `cipher_key`. If either of
these leaked then the security of the cipher is compromised.  These are a ways I am aware they
could leak:

1) Logging (easily avoided).
2) Memory being released without being cleared.
3) Memory being written to persistent storage.

This crate only handles the `password` as a reference `&[u8]`. As mentioned, the `password` is
passed to the proof of work function. As the current proof of work function has been developed for
password hashing I am assuming that it has taken reasonable precautions, but am not in a
position to guarantee this.

The `cipher_key` is both generated and consumed within this crate.
To give it some protection, the proof of work function returns the result wrapped as a SecretVec
to ensure that the `cipher_key` is cleared before the memory is released.

Neither of these address the third problem, i.e., secrets being written to persistent
storage.

#### Fixed Argon2 "secret"

Argon2 supports use of a secret.  This can be used a 'pepper'. Unlike a salt, a pepper is
not stored along side the hash and can be reused across multiple passwords. Typically it
is long and may be stored be in some trusted hardware store.  This secret means that an attacker
in possession of the hashed password and salt still has a missing component.

In this library Argon2 is not being used to verify password, but as a proof of work
function. So although the salt is stored, the hashed password is never exposed (it is
directly used as the `cipher_key`). This means there is limited risk of the attacker gaining access
to the `salt` and hashed password.

Current version: 0.2.0

This is a hobby project; I don't have the bandwidth
to properly maintain this.  You are welcome to use
and fork at your risk, but I would not recommend this
crate for any serious work.

License: MIT/Apache-2.0
