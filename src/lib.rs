//! # Slow Lock
//!
//! Slow lock is an adapter that combines an AEAD cipher and a proof of work
//! function to create an encryption primitive that has tuneable resistance to
//! brute force attacks.
//!
//! Currently the only implementation of the proof of work function is based
//! on Argon2.
//!
//!
//! ## Design Choices (for review)
//!
//! This is a log of design choices I have made in this library. I am not a security
//! expert and these may be wrong - so I'm calling them out here so that users are
//! pre-warned.  Any review gratefully received.
//!
//! ### Fixed Argon2 "secret"
//!
//! Argon2 supports use of a secret.  This can be used a 'pepper'. Unlike a salt, a pepper is
//! not stored along side the hash and can be reused across multiple passwords. Typically it
//! is long and may stored be in some trusted hardware store.  This secret means that an attacker
//! in possession of the hashed password and salt still has a missing component.
//!
//! In this library Argon2 is not being used to verify password, but as a proof of work
//! function. So although the salt is stored, the hashed password is never exposed (it is
//! directly used as associated data). This means there is no risk of the attacker gaining access
//! to the salt and hashed password.
//!
//! ### Key is based on password and nonce
//!
//!
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use aead::{AeadInPlace, NewAead, Nonce, Tag};
use aead::generic_array::{ArrayLength, GenericArray};
use aead::generic_array::typenum::consts::U32;
use rand::RngCore;
use sha2::Digest;
use sysinfo::SystemExt;

#[cfg(feature="logging")]
use log::info;

/// Library error types
#[derive(Debug)]
pub enum Error {
    // Encrypt/decrypt operation failed. Probably due to bad key
    AeadOperationFailed,

    /// The proof of work function failed to generate a valid proof of work.
    /// This is normally because the proof of work parameters are invalid.
    ProofOfWorkFailed(String),

    /// When the time lock is encrypted or decrypted it performs a proof of work to
    /// slow brute force attacks. Each execution of the proof of work is timed.
    /// If it takes less that the expected `minimum_duration` this error is returned
    /// to warn users.  This can happen when the `WorkFunction` was tuned in a low performance
    /// environment and is subsequently used in a higher performance environment.
    ProofOfWorkCompletedTooQuickly,
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::ProofOfWorkFailed(format!("{:?}", e))
    }
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Error::AeadOperationFailed
    }
}

/// Key function can turn content into a key of the correct size.
///
/// Implementations of this interface are responsible for making sure
/// the conversion process takes an appropriate amount of computational effort.
///
pub trait WorkFunction: Sized {
    fn make_key<K>(&self, content: &[u8]) -> Result<GenericArray<u8, K>, Error>
        where
            K: ArrayLength<u8>;

    /// Attempt to create work function that will take approximately
    /// the `target_duration`.
    ///
    /// # Arguments
    /// * `target_duration` - how long the work function should take
    /// * `verbose` - if compiled with `log` support and `verbose` is true the algorithm should
    /// log its attempts to tune the duration.
    ///
    fn calibrate(target_duration: Duration, verbose: bool) -> Result<Self, Error>;
}

/// Key function based on Argon2.
pub struct Argon2WorkFunction {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
    pub salt: [u8; 32],
}

/// Default `mem_cost` as a percentage of total system memory.
const DEFAULT_MEM_PERCENT: u64 = 5;

impl WorkFunction for Argon2WorkFunction {
    fn make_key<K>(&self, content: &[u8]) -> Result<GenericArray<u8, K>, Error>
        where
            K: ArrayLength<u8>,
    {
        let config = argon2::Config {
            ad: &[],
            hash_length: K::to_u32(),
            lanes: self.lanes,
            mem_cost: self.mem_cost,
            secret: &[],
            thread_mode: argon2::ThreadMode::Parallel,
            time_cost: self.time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        };

        Ok(GenericArray::clone_from_slice(&argon2::hash_raw(
            content, &self.salt, &config,
        )?))
    }


    fn calibrate(target_duration: Duration, verbose: bool) -> Result<Argon2WorkFunction, Error> {
        Self::calibrate(target_duration, verbose, DEFAULT_MEM_PERCENT)
    }
}

impl Argon2WorkFunction {

    fn calibrate(
        target_duration: Duration,
        verbose: bool,
        memory_percent: u64,
    ) -> Result<Argon2WorkFunction, Error> {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();

        let total_mem = system.get_total_memory();
        let num_cpus = system.get_processors().len() as u32;

        let lanes = num_cpus * 2;
        let mem_cost = (total_mem * memory_percent / 100) as u32;
        let time_cost = 1;
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        #[cfg(feature="logging")]
        if verbose {
            info!("Initialized mem to {}kb ({}% of total memory, {}km).", mem_cost, memory_percent, total_mem);
            info!("Initialized lanes to {} (2x num cpus).", lanes);
        }

        let mut work = Argon2WorkFunction {
            mem_cost,
            time_cost,
            lanes,
            salt,
        };

        let mut duration = work.estimate_duration()?;

        // increase time cost until we are above the target.
        while duration < target_duration {
            let scale = target_duration.as_micros() as f64 / duration.as_micros() as f64;
            let next_time_cost = (work.time_cost as f64 * scale).ceil() as u32;

            #[cfg(feature="logging")]
            if verbose {
                info!("Estimated duration {}ms is too low, increasing time_cost from {} to {}.",
                      duration.as_millis(), work.time_cost, next_time_cost);
            }

            work.time_cost = next_time_cost;
            duration = work.estimate_duration()?;
        }

        // then tune memory until we are within 5% of target duration.
        let tolerance_ms = (target_duration.as_millis() * 5) / 100;
        let tolerance = Duration::from_millis(tolerance_ms as u64);
        let lo = target_duration - tolerance;
        let hi = target_duration + tolerance;


        while duration < lo || duration > hi {
            let scale = target_duration.as_micros() as f64 / duration.as_micros() as f64;
            let next_mem_cost = (work.mem_cost as f64 * scale) as u32;

            #[cfg(feature="logging")]
            if verbose {
                if duration < lo {
                    info!("Estimated duration {}ms is too low, increasing mem_cost from {}kb to {}kb.",
                          duration.as_millis(), work.mem_cost, next_mem_cost)
                } else {
                    info!("Estimated duration {}ms is too high, decreasing mem_cost from {}kb to {}kb.",
                          duration.as_millis(), work.mem_cost, next_mem_cost)
                }
            }

            work.mem_cost = next_mem_cost;
            duration = work.estimate_duration()?;
        }

        #[cfg(feature="logging")]
        if verbose {
            info!("Calibration complete, estimated duration={}ms, mem_cost={}kb, time_cost={}, lanes={}.",
                  duration.as_millis(), work.mem_cost, work.time_cost, work.lanes);
        }

        Ok(work)
    }


    fn estimate_duration(&self) -> Result<Duration, Error> {
        let now = Instant::now();
        let _key: GenericArray<u8, U32> = self.make_key(&[0u8; 32])?;
        Ok(now.elapsed())
    }
}

pub struct SlowLock<P, A, W> {
    password: P,
    work_function: W,
    _phantom: PhantomData<A>,
}

impl<P, A, W> SlowLock<P, A, W>
    where
        P: AsRef<[u8]>,
        A: AeadInPlace + NewAead,
        W: WorkFunction,
{
    pub fn new(password: P, key_function: W) -> SlowLock<P, A, W> {
        SlowLock {
            password,
            work_function: key_function,
            _phantom: PhantomData {},
        }
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, Error> {
        self.make_cipher(nonce).and_then(|(algo, _duration)| {
            algo.encrypt_in_place_detached(nonce, &associated_data, buffer)
                .map_err(|_| Error::AeadOperationFailed)
        })
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        self.make_cipher(nonce).and_then(|(algo, _duration)| {
            algo.decrypt_in_place_detached(nonce, &associated_data, buffer, tag)
                .map_err(|_| Error::AeadOperationFailed)
        })
    }

    fn make_cipher(&self, nonce: &Nonce<Self>) -> Result<(A, Duration), Error> {
        // make unique key_content by combining key_hash + nonce data using SHA-256
        let mut digest = sha2::Sha256::new();
        digest.update(self.password.as_ref());
        digest.update(nonce.as_slice());
        let key_content = digest.finalize();

        let now = Instant::now();
        let cipher_key = self.work_function.make_key(&key_content)?;
        let work_duration = now.elapsed();

        Ok((A::new(&cipher_key), work_duration))
    }
}

impl<P, A, W> aead::AeadCore for SlowLock<P, A, W>
    where
        A: AeadInPlace + NewAead,
{
    type NonceSize = A::NonceSize;
    type TagSize = A::TagSize;
    type CiphertextOverhead = A::CiphertextOverhead;
}

impl<P, A, W> AeadInPlace for SlowLock<P, A, W>
    where
        P: AsRef<[u8]>,
        A: AeadInPlace + NewAead,
        W: WorkFunction,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, aead::Error> {
        self.encrypt_in_place_detached(nonce, associated_data, buffer)
            .map_err(|_| aead::Error)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), aead::Error> {
        self.decrypt_in_place_detached(nonce, associated_data, buffer, tag)
            .map_err(|_| aead::Error)
    }
}

#[cfg(test)]
mod test {
    use aead::{Aead, AeadInPlace, NewAead};
    use aead::generic_array::GenericArray;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    use crate::{Argon2WorkFunction, SlowLock, WorkFunction};

    fn test_work_function() -> Argon2WorkFunction {
        Argon2WorkFunction {
            mem_cost: 4096,
            time_cost: 2,
            lanes: 3,
            salt: [0u8; 32],
        }
    }


    #[test]
    fn can_use_aes_gcm256_with_argon2_work_function() {
        let work_fn = test_work_function();
        let algo: SlowLock<_, Aes256Gcm, _> = SlowLock::new("thing", work_fn);

        round_trip(&algo, [0u8; 12]);
    }

    #[test]
    fn can_use_aes_gcm128_with_argon2_work_function() {
        let work_fn = test_work_function();
        let algo: SlowLock<_, Aes128Gcm, _> = SlowLock::new("thing", work_fn);

        round_trip(&algo, [0u8; 12]);
    }

    fn round_trip<P, A, K, D>(algo: &SlowLock<P, A, K>, nonce: D)
        where
            D: AsRef<[u8]>,
            P: AsRef<[u8]>,
            A: AeadInPlace + NewAead,
            K: WorkFunction,
    {
        let data = "message text".as_bytes();
        let nonce = nonce.as_ref();

        let encrypted = algo
            .encrypt(GenericArray::from_slice(nonce), &data[..])
            .unwrap();

        let decrypted = algo
            .decrypt(GenericArray::from_slice(nonce), encrypted.as_slice())
            .unwrap();

        assert_eq!(data, &decrypted);
    }
}
