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

use aead::generic_array::typenum::consts::U32;
use aead::generic_array::{ArrayLength, GenericArray};
use aead::{AeadInPlace, NewAead, Nonce, Tag};
#[cfg(feature = "logging")]
use log::info;
use rand::RngCore;
use sha2::Digest;
use sysinfo::{System, SystemExt};

/// Library error types
#[derive(Debug, Eq, PartialEq)]
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
}

/// Key function based on Argon2.
pub struct Argon2WorkFunction {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
    pub salt: [u8; 32],
}

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
}

/// A builder that can be used to calibrate a [Argon2WorkFunction] to take an approximate duration.
/// ```
/// use slowlock::Error;
/// # fn main() -> Result<(), Error> {
///
/// use slowlock::Argon2WorkFunctionCalibrator;
/// use std::time::Duration;
///
/// // Try to create a lock that uses a takes about 2.5s to process.
/// let lock = Argon2WorkFunctionCalibrator::new()
///                 .calibrate(Duration::from_millis(2500))?;
///
/// # Ok(()) }
/// ```
pub struct Argon2WorkFunctionCalibrator {
    memory_hint_percent: Option<f64>,
    memory_hint_kb: Option<u32>,
    lanes: Option<u32>,
    verbose: bool,
}

const DEFAULT_MEMORY_HINT_PERCENT: f64 = 5.0;

impl Default for Argon2WorkFunctionCalibrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Argon2WorkFunctionCalibrator {
    /// Create a new calibrator with default parameters.
    pub fn new() -> Argon2WorkFunctionCalibrator {
        Argon2WorkFunctionCalibrator {
            memory_hint_percent: None,
            memory_hint_kb: None,
            lanes: None,
            verbose: false,
        }
    }

    /// Set how much memory (as percentage of total memory) the work function should aim to use.
    ///
    /// The calibration process will attempt to use approximately this much memory.
    /// The higher the memory usage is the harder it will be for an attacker to
    /// scale brute force attacks.  By default 5% of total memory is used.
    ///
    /// To set the suggested memory hint directly see [Argon2WorkFunctionCalibrator::memory_hint_kb].
    ///
    ///
    /// # Arguments
    /// * `percent` - what percent of total memory should be used (`0.0` -> `100.0`)
    ///
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::Argon2WorkFunctionCalibrator;
    /// use std::time::Duration;
    ///
    /// // Try to create a lock that uses approximately 7.3% of total memory and takes
    /// // about 2.5s to process
    /// let lock = Argon2WorkFunctionCalibrator::new()
    ///                 .memory_hint_percent(7.3)
    ///                 .calibrate(Duration::from_millis(2500))?;
    ///
    /// # Ok(()) }
    /// ```
    pub fn memory_hint_percent(mut self, percent: f64) -> Argon2WorkFunctionCalibrator {
        self.memory_hint_percent = Some(percent);
        self
    }

    /// Set how much memory (in kb) the work function should aim to use.
    ///
    /// The calibration process will attempt to use approximately this much memory.
    /// The higher the memory usage is the harder it will be for an attacker to
    /// scale brute force attacks.
    ///
    /// To set the suggest memory as percentage of total memory see
    /// [Argon2WorkFunctionCalibrator::memory_hint_percent]
    ///
    /// # Arguments
    /// * `hint` - how much memory to use in kb.
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::Argon2WorkFunctionCalibrator;
    /// use std::time::Duration;
    ///
    /// // Try to create a lock that uses approximately 4096kb of memory and takes
    /// // about 2.5s to process.
    /// let lock = Argon2WorkFunctionCalibrator::new()
    ///                 .memory_hint_kb(4096)
    ///                 .calibrate(Duration::from_millis(2500))?;
    ///
    /// # Ok(()) }
    /// ```
    pub fn memory_hint_kb(mut self, hint_kb: u32) -> Argon2WorkFunctionCalibrator {
        self.memory_hint_kb = Some(hint_kb);
        self
    }

    /// Set how much lanes the work function will use.
    ///
    /// By default the work function will use two lanes for each CPU.
    ///
    /// # Arguments
    /// * `lanes` - how much memory to use in kb.
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::Argon2WorkFunctionCalibrator;
    /// use std::time::Duration;
    ///
    /// // Try to create a lock that uses four lanes and takes about 2.5s to process.
    /// let lock = Argon2WorkFunctionCalibrator::new()
    ///                 .lanes(4)
    ///                 .calibrate(Duration::from_millis(2500))?;
    ///
    /// # Ok(()) }
    /// ```
    pub fn lanes(mut self, lanes: u32) -> Argon2WorkFunctionCalibrator {
        self.lanes = Some(lanes);
        self
    }

    /// Set calibrator to report progress to log
    ///
    /// # Arguments
    /// * `verbose` - if compiled with `log` support and `verbose` is true the algorithm
    /// will log its attempts to calibrate the duration.
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::Argon2WorkFunctionCalibrator;
    /// use std::time::Duration;
    ///
    /// // Try to create a lock that takes about 2.5s to process and log progress
    /// // Only actually logs if the `logging` feature has been enabled.
    /// let lock = Argon2WorkFunctionCalibrator::new()
    ///                 .verbose(true)
    ///                 .calibrate(Duration::from_millis(2500))?;
    ///
    /// # Ok(()) }
    /// ```
    pub fn verbose(mut self, verbose: bool) -> Argon2WorkFunctionCalibrator {
        self.verbose = verbose;
        self
    }

    /// Attempt to create work function that will take approximately
    /// the `target_duration`.
    ///
    /// # Arguments
    /// * `target_duration` - how long the work function should take to complete
    ///
    pub fn calibrate(self, target_duration: Duration) -> Result<Argon2WorkFunction, Error> {
        let mut work = self.initialize_base_line();

        let rough = self.calibrate_time_cost(target_duration, &mut work)?;
        let adjusted = self.calibrate_mem_cost(target_duration, &mut work, rough)?;

        #[cfg(feature = "logging")]
        if self.verbose {
            info!("Calibration complete, estimated duration={}ms, mem_cost={}kb, time_cost={}, lanes={}.",
                  adjusted.as_millis(), work.mem_cost, work.time_cost, work.lanes);
        }

        Ok(work)
    }

    fn initialize_base_line(&self) -> Argon2WorkFunction {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();

        let mem_cost = self
            .memory_hint_kb
            .unwrap_or_else(|| self.pick_percent_of_total_memory(&system));

        let lanes = self.lanes.unwrap_or_else(|| self.pick_num_lanes(&system));

        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        Argon2WorkFunction {
            mem_cost,
            time_cost: 1,
            lanes,
            salt,
        }
    }

    fn pick_percent_of_total_memory(&self, system: &System) -> u32 {
        let memory_hint_percent = self
            .memory_hint_percent
            .unwrap_or(DEFAULT_MEMORY_HINT_PERCENT);

        let memory_factor = memory_hint_percent as f64 / 100.0;

        let total_mem = system.get_total_memory();

        let mem_cost = (total_mem as f64 * memory_factor) as u32;

        #[cfg(feature = "logging")]
        if self.verbose {
            info!(
                "Initialized mem to {}kb ({:0.02}% of total memory, {}kb).",
                mem_cost, memory_hint_percent, total_mem
            );
        }

        mem_cost
    }

    fn pick_num_lanes(&self, system: &System) -> u32 {
        let num_cpus = system.get_processors().len() as u32;
        let lanes = num_cpus * 2;

        #[cfg(feature = "logging")]
        if self.verbose {
            info!("Initialized lanes to {} (2x num cpus).", lanes);
        }

        lanes
    }

    // Increase `time_cost` until the duration is longer than the `target_duration`.
    fn calibrate_time_cost(
        &self,
        target_duration: Duration,
        work: &mut Argon2WorkFunction,
    ) -> Result<Duration, Error> {
        let mut duration = work.estimate_duration()?;
        while duration < target_duration {
            let scale = target_duration.as_micros() as f64 / duration.as_micros() as f64;
            let next_time_cost = (work.time_cost as f64 * scale).ceil() as u32;

            #[cfg(feature = "logging")]
            if self.verbose {
                info!(
                    "Estimated duration {}ms is too low, increasing time_cost from {} to {}.",
                    duration.as_millis(),
                    work.time_cost,
                    next_time_cost
                );
            }

            work.time_cost = next_time_cost;
            duration = work.estimate_duration()?;
        }
        Ok(duration)
    }

    // Adjust `mem_cost` until we are within 5% of the `target_duration`.
    fn calibrate_mem_cost(
        &self,
        target_duration: Duration,
        work: &mut Argon2WorkFunction,
        baseline: Duration,
    ) -> Result<Duration, Error> {
        let mut duration = baseline;

        let tolerance_ms = (target_duration.as_millis() * 5) / 100;
        let tolerance = Duration::from_millis(tolerance_ms as u64);
        let lo = target_duration - tolerance;
        let hi = target_duration + tolerance;

        while duration < lo || duration > hi {
            let scale = target_duration.as_micros() as f64 / duration.as_micros() as f64;
            let next_mem_cost = (work.mem_cost as f64 * scale) as u32;

            #[cfg(feature = "logging")]
            if self.verbose {
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

        Ok(duration)
    }
}

impl Argon2WorkFunction {
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
    use aead::generic_array::GenericArray;
    use aead::{Aead, AeadInPlace, NewAead};
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

    #[test]
    fn decrypt_fails_if_password_is_wrong() {
        let data = "message text".as_bytes();

        let work_fn1 = test_work_function();
        let work_fn2 = test_work_function();

        let algo1: SlowLock<_, Aes256Gcm, _> = SlowLock::new("thing1", work_fn1);
        let algo2: SlowLock<_, Aes256Gcm, _> = SlowLock::new("thing2", work_fn2);

        let encrypted = algo1
            .encrypt(GenericArray::from_slice(&[0u8; 12]), &data[..])
            .unwrap();

        let err = algo2
            .decrypt(GenericArray::from_slice(&[0u8; 12]), encrypted.as_slice())
            .err()
            .unwrap();

        assert_eq!(aead::Error, err);
    }

    #[test]
    fn decrypt_fails_if_nonce_is_wrong() {
        let data = "message text".as_bytes();

        let work_fn = test_work_function();
        let algo: SlowLock<_, Aes256Gcm, _> = SlowLock::new("thing1", work_fn);

        let encrypted = algo
            .encrypt(GenericArray::from_slice(&[0u8; 12]), &data[..])
            .unwrap();

        let err = algo
            .decrypt(GenericArray::from_slice(&[1u8; 12]), encrypted.as_slice())
            .err()
            .unwrap();

        assert_eq!(aead::Error, err);
    }
}
