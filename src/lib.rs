//! # Slow Lock
//!
//! Slow is a thin convenience layer that makes it easy to use a proof of work function
//! to recover a cipher key.
//!
//! It implements no new cryptographic primitives, instead in provides some mechanisms to
//!
//! 1) Help calibrate the proof of work function to take a reasonable amount of time
//! 2) Detect when a previously configured proof of work function is no-long adequate
//!
//! Currently the only implementation of the proof of work function is based
//! on Argon2.
//!
//!
//! Basic process:
//!
//! 1. `password` is passed through proof of work function to create `cipher_key`.
//! 3. `cipher_key` and `nonce` are used to decrypt/encrypt content.
//!
//! To be useful, the proof of work function must take a reasonable amount of time/effort
//! to complete. This crates provides a [Argon2WorkFunctionCalibrator] that can be used to
//! create work functions with variable target durations.
//!
//! Machine performance improves year on year, so we need to occasionally recalibrate
//! the work function to ensure it continues to present an adequate challenge.  This crate
//! does not automatically change the work function.  Instead, it measures its duration
//! and provides a mechanism to alert the calling code when the proof of work function
//! completes too quickly. These are controlled by the [WorkPolicy]. There are currently
//! two ways the work policy can alert the user if a proof of work function completes too
//! quickly:
//!
//! 1) If the `log_warning` policy is enabled, a message is written to the logs
//! 2) If the `return_error` policy is enabled, an error is returned
//!
//! Both `log_warning` and `return_error` are enabled by default. The exact trigger
//! levels can be tuned as percentage of the target duration.
//!
//! Separately, if the proof of work function is calibrated in debug mode, a warning is
//! generated as the parameters will be far to weak.
//!
//! ## Design Choices (for review)
//!
//! This is a log of design choices I have made in this library. I am not a security
//! expert and these may be wrong - so I'm calling them out here so that users are
//! pre-warned.  Any review gratefully received.
//!
//! ### Trustworthy Work Function
//!
//! Currently the `password` is passed to the proof of work function and the output of
//! the proof of work function is used as the `cipher_key`.
//!
//! So as well as being a proof of work function, it is also performing any necessary
//! key widening.  It would seem cleaner to separate these responsibilities. Decoupling
//! would, of course, introduce its own complexity.  Given the current proof of
//! work function is explicitly designed with key-widening in mind this complexity
//! has been avoided.
//!
//! If better separation of is real value (feed-back welcome) an alternative approach would be:
//!
//! 1) Pass hash of `password` to proof of work function
//! 2) Combine proof of work output with original `password` to make `cipher_key`.
//!
//! This would prevent leakages in the proof of work function revealing either the `password`
//! or the `cipher_key`.  To do this I would need some way of safely performing step 2.
//! I assume that for a 256 bit cipher, combining the `password` and proof of work using `SHA-256`
//! would be acceptable.  I don't currently see a nice way to make this work on range
//! of cipher-key lengths. A review of <https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml>
//! suggest that  128 and 256 are by far the most common key lengths.
//!
//! ### Secret Hygiene
//!
//! The crate handles two secrets, the original `password` and the `cipher_key`. If either of
//! these leaked then the security of the cipher is compromised.  These are a ways I am aware they
//! could leak:
//!
//! 1) Logging (easily avoided).
//! 2) Memory being released without being cleared.
//! 3) Memory being written to persistent storage.
//!
//! This crate only handles the `password` as a reference `&[u8]`. As mentioned, the `password` is
//! passed to the proof of work function. As the current proof of work function has been developed for
//! password hashing I am assuming that it has taken reasonable precautions, but am not in a
//! position to guarantee this.
//!
//! The `cipher_key` is both generated and consumed within this crate.
//! To give it some protection, the proof of work function returns the result wrapped as a SecretVec
//! to ensure that the `cipher_key` is cleared before the memory is released.
//!
//! Neither of these address the third problem, i.e., secrets being written to persistent
//! storage.
//!
//! ### Fixed Argon2 "secret"
//!
//! Argon2 supports use of a secret.  This can be used a 'pepper'. Unlike a salt, a pepper is
//! not stored along side the hash and can be reused across multiple passwords. Typically it
//! is long and may be stored be in some trusted hardware store.  This secret means that an attacker
//! in possession of the hashed password and salt still has a missing component.
//!
//! In this library Argon2 is not being used to verify password, but as a proof of work
//! function. So although the salt is stored, the hashed password is never exposed (it is
//! directly used as the `cipher_key`). This means there is limited risk of the attacker gaining access
//! to the `salt` and hashed password.
//!
//! ## Basic Usage
//! ```
//! # use slowlock::Error;
//! # fn main() -> Result<(), Error> {
//! use slowlock::{WorkPolicyBuilder, Argon2WorkFunctionCalibrator, NewSlowAead};
//! use std::time::Duration;
//! use hex_literal::hex;
//! use aes_gcm::Aes256Gcm;
//! use aead::Aead;
//! use aead::generic_array::GenericArray;
//!
//! let target_duration = Duration::from_millis(2500);
//!
//! // Create a policy with a target duration of 2.5s that will:
//! //  * log a warning if the proof of work function takes less than 75% of the target duration
//! //  * return an error if the proof of work function takes less than 30% of target duration.
//! let policy = WorkPolicyBuilder::default()
//!                 .build(target_duration);
//!
//! // Try to create a lock that uses approximately 5% of total memory and takes
//! // about 2.5s to process
//! let work_fn = Argon2WorkFunctionCalibrator::default()
//!           .calibrate(target_duration)?;
//!
//! // User supplied secret. This could be a password or a key recovered
//! // from an earlier stage in the decryption/encryption process.
//! let password = "super secret password".as_bytes();
//!
//! // Salt should be generated using a cryptographically secure pseudo-random number generator
//! // It needs to be stored alongside the encrypted values
//! let salt = hex!("8a248444f2fc50308a856b35de67b312a4c4be1d180f49e101bf6330af5d47");
//!
//! // Attempt to create the cipher algorithm using the work function and checking the
//! // policy.
//! // This process should take about 2.5 seconds.
//! let algo: Aes256Gcm = work_fn.slow_new(&password, &salt, &policy)?;
//!
//!
//! // Nonce _must_ be unique each time data is encrypted with the same cipher_key.
//! // If the salt if changed the cipher_key is implicitly changed so the nonce
//! // could be reset.
//! let nonce = hex!("1d180f49e101bf6330af5d47");
//!
//! let plain_text = "secret content to protect".as_bytes();
//!
//! let cipher_text = algo.encrypt(
//!      GenericArray::from_slice(&nonce),
//!      plain_text
//! )?;
//!
//! let recovered_plain_text = algo.decrypt(
//!     GenericArray::from_slice(&nonce),
//!     cipher_text.as_slice()
//! )?;
//!
//! assert_eq!(plain_text, recovered_plain_text);
//!
//! # Ok(()) }
//! ```
//!
use std::time::{Duration, Instant};

use aead::generic_array::GenericArray;
use aead::generic_array::typenum::Unsigned;
use aead::NewAead;
#[cfg(feature = "logging")]
use log::{info, warn};
use secrecy::{ExposeSecret, SecretVec};
use sysinfo::{System, SystemExt};


/// Library error types
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Encrypt/decrypt operation failed.
    /// This can be useful when working with code that is both using Aead functions
    /// and functions from this crate.
    AeadOperationFailed,

    /// The proof of work function failed to generate a valid proof of work.
    /// This is normally because the proof of work parameters are invalid.
    ProofOfWorkFailed(String),

    /// When the time lock is encrypted or decrypted it performs a proof of work to
    /// slow brute force attacks. Each execution of the proof of work is timed.
    /// If it takes less that the expected `minimum_duration` this error is returned
    /// to warn users.  This can happen when the `WorkFunction` was tuned in a low performance
    /// environment and is subsequently used in a higher performance environment.
    ProofOfWorkCompletedTooQuickly {
        target_duration_ms: u32,
        actual_duration_ms: u32,
    },
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Error::AeadOperationFailed
    }
}

pub trait NewSlowAead<A> {
    /// Create a new AEAD instance by passing the password through a proof of work function.
    /// # Arguments
    /// * `password` - secret data supplied by user
    /// * `salt` - pseudo-random data stored with secured data to ensure that users with same
    /// `password` end up with different `cipher_key`s.
    /// * `policy` - a policy that will control behaviour if the work function completes too quickly.
    ///
    /// # Errors
    ///
    /// Will return an error if proof of work functions parameters are not valid.
    ///
    fn slow_new(&self, password: &[u8], salt: &[u8], policy: &WorkPolicy) -> Result<A, Error>;
}

/// NewSlowAead is implemented for anything that implements a work function.
impl<W, A> NewSlowAead<A> for W
where
    W: WorkFunction,
    A: NewAead,
{
    fn slow_new(&self, password: &[u8], salt: &[u8], policy: &WorkPolicy) -> Result<A, Error> {
        let now = Instant::now();
        let key = self.make_cipher_key(A::KeySize::to_u32(), password, salt)?;
        let actual_duration_ms = now.elapsed().as_millis() as u32;
        policy.check_duration(actual_duration_ms)?;
        Ok(A::new(GenericArray::from_slice(key.expose_secret())))
    }
}

/// Work function can turn content into a key of the correct size.
///
/// Implementations of this interface are responsible for making sure
/// the conversion process takes an appropriate amount of computational effort.
///
pub trait WorkFunction: Sized {
    /// Generate a `cipher_key` from a `password` and a `salt`.
    ///
    /// # Arguments
    /// * `work_size` - how big the proof of work should be
    /// * `password` - secret data supplied by user
    /// * `salt` - pseudo-random data stored with secured data to ensure that users with same
    /// `password` end up with different `cipher_key`s.
    ///
    fn make_cipher_key(
        &self,
        work_size: u32,
        password: &[u8],
        salt: &[u8],
    ) -> Result<SecretVec<u8>, Error>;
}

/// Work function based on Argon2.
///
/// | Parameter       | Value                                                                    |
/// | --------------- | ------------------------------------------------------------------------ |
/// | Algorithm       | `Argon2`                                                                 |
/// | Reference       | [draft irtf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/)   |
/// | Salt            | Supplied by user                                                         |
/// | Parallelism     | Automatically calibrated to twice number of cpus                         |
/// | Tag Length      | Automatically set to match KeySize of AEAD                               |
/// | Memory Size     | Automatically calibrated (defaults to approxmately 5% of total memory)   |
/// | Iterations      | Automatically calibrated                                                 |
/// | Version         | 0x13 (i.e. version 1.3 of Argon2)                                        |
/// | Variant         | Argon2id  (hybrid resistant to side-channel and gpu attacks)             |
/// | Key             | Not used                                                                 |
/// | Associated Data | Not used                                                                 |
///
/// ```
/// # use slowlock::Error;
/// # fn main() -> Result<(), Error> {
/// use std::time::Duration;
/// use aead::generic_array::{GenericArray, typenum::U32};
/// use hex_literal::hex;
/// use slowlock::{Argon2WorkFunction, WorkFunction};
/// use secrecy::ExposeSecret;
///
/// // Normally you should use the `Argon2WorkFunctionCalibrator`, but to make sure we
/// // get exactly the same configuration we are going to fix the parameters.
/// let work_fn = Argon2WorkFunction {
///     mem_cost: 4096,
///     time_cost: 12,
///     lanes: 10
/// };
///
/// // User supplied secret. This could be a password or a key recovered
/// // from an earlier stage in the decryption/encryption process.
/// let password = "super secret password".as_bytes();
///
/// // Salt should be generated using a cryptographically secure pseudo random number generator
/// let salt = hex!("8a248444f2fc50308a856b35de67b312a4c4be1d180f49e101bf6330af5d47");
///
/// let key = work_fn.make_cipher_key(32, password, &salt)?;
///
/// let expected_key = &hex!("a2867fb2a2ddb384cba4f382f5db48b36066cbcb755ed7f07aeabef1f98fbf54");
/// assert_eq!(expected_key, key.expose_secret().as_slice());
///
/// # Ok(()) }
/// ```
pub struct Argon2WorkFunction {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::ProofOfWorkFailed(format!("{:?}", e))
    }
}

impl WorkFunction for Argon2WorkFunction {
    fn make_cipher_key(&self, work_size: u32, password: &[u8], salt: &[u8]) -> Result<SecretVec<u8>, Error>
    {
        let config = argon2::Config {
            ad: &[],
            hash_length: work_size,
            lanes: self.lanes,
            mem_cost: self.mem_cost,
            secret: &[],
            thread_mode: argon2::ThreadMode::Parallel,
            time_cost: self.time_cost,
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
        };

        argon2::hash_raw(password, salt, &config)
            .map_err(|e| e.into())
            .map(SecretVec::new)
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
/// // Try to create a lock that uses a takes about 2s to process.
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
    /// let lock = Argon2WorkFunctionCalibrator::default()
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

    /// Set how many processing lanes the work function will use.
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

        #[cfg(debug_assertions)] {
            #[cfg(logging)] {
                warn!("Calibrating proof of work function in debug bug - the parameters generated will be too weak.")
            }
        }


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

        Argon2WorkFunction {
            mem_cost,
            time_cost: 1,
            lanes,
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

            if duration < lo {
                #[cfg(feature = "logging")]
                if self.verbose {
                    info!("Estimated duration {}ms is too low, increasing mem_cost from {}kb to {}kb.",
                          duration.as_millis(), work.mem_cost, next_mem_cost)
                }
            } else {
                #[cfg(feature = "logging")]
                if self.verbose {
                    info!("Estimated duration {}ms is too high, decreasing mem_cost from {}kb to {}kb.",
                          duration.as_millis(), work.mem_cost, next_mem_cost);
                }

                if next_mem_cost < work.lanes * 8 {
                    #[cfg(feature = "logging")]
                    if self.verbose {
                        warn!("Although too high, using mem_cost as next adjustment will take it below lowest limit.\
                         This likely means that you have far too little memory allocated to Argon2")
                    }
                    break;
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
        self.make_cipher_key(32, &[0u8; 32], &[0u8; 32])?;
        Ok(now.elapsed())
    }
}

const DEFAULT_LOG_WARNING_TRIGGER_PERCENT: u32 = 75;
const DEFAULT_RETURN_ERROR_TRIGGER_PERCENT: u32 = 30;

pub struct WorkPolicyBuilder {
    log_warning_enabled: Option<bool>,
    log_warning_trigger_percent: Option<u32>,
    return_error_enabled: Option<bool>,
    return_error_trigger_percent: Option<u32>,
}

impl Default for WorkPolicyBuilder {
    fn default() -> Self {
        WorkPolicyBuilder::new()
    }
}

/// WorkPolicyBuilder allows users to configure a [WorkPolicy] with sensible defaulting.
///
/// ```
/// # use slowlock::Error;
/// # fn main() -> Result<(), Error> {
/// use slowlock::{WorkPolicyBuilder, Argon2WorkFunctionCalibrator, NewSlowAead};
/// use std::time::Duration;
/// use aes_gcm::Aes256Gcm;
///
/// let target_duration = Duration::from_millis(2500);
///
/// // Create a policy with a target duration of 2.5s that will:
/// //  * log a warning if the proof of work function takes less than 75% of the target duration
/// //  * return an error if the proof of work function takes less than 30% of target duration.
/// let policy = WorkPolicyBuilder::default()
///                 .build(target_duration);
///
/// // Try to create a lock that uses approximately 7.3% of total memory and takes
/// // about 2.5s to process
/// let work_fn = Argon2WorkFunctionCalibrator::default()
///                 .memory_hint_percent(7.3)
///                 .calibrate(target_duration)?;
///
/// // Attempt to create the cipher algorithm using the work function and checking the
/// // policy.
/// let algo: Aes256Gcm = work_fn.slow_new(b"password", &[0u8; 32], &policy)?;
/// # Ok(()) }
/// ```
impl WorkPolicyBuilder {
    /// Create a new calibrator with default parameters.
    pub fn new() -> WorkPolicyBuilder {
        WorkPolicyBuilder {
            log_warning_enabled: None,
            log_warning_trigger_percent: None,
            return_error_enabled: None,
            return_error_trigger_percent: None,
        }
    }

    /// Control whether work function will return an error response if it completes too quickly.
    ///
    /// # Arguments
    /// * `enabled` - if set to false the policy will never return an error. if set to true
    /// the policy will return an error if the proof of work function completes too quickly.
    ///
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::WorkPolicyBuilder;
    /// use std::time::Duration;
    ///
    /// // Create a policy with a target duration of 2.5s that will never return an error.
    /// let policy = WorkPolicyBuilder::default()
    ///                 .return_error(false)
    ///                 .build(Duration::from_millis(2500));
    ///
    /// # Ok(()) }
    /// ```
    pub fn return_error(mut self, enabled: bool) -> WorkPolicyBuilder {
        self.return_error_enabled = Some(enabled);
        self
    }

    /// Control how quickly the proof of work must complete to return an error.
    ///
    /// # Arguments
    /// * `percent` - percentage of target duration below which a error will be returned
    ///
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::WorkPolicyBuilder;
    /// use std::time::Duration;
    ///
    /// // Create a policy with a target duration of 2.5s that will return an error
    /// // if the proof of work function takes less than 35% of the target duration.
    /// let policy = WorkPolicyBuilder::default()
    ///                 .return_error_threshold(35)
    ///                 .build(Duration::from_millis(2500));
    ///
    /// # Ok(()) }
    /// ```
    pub fn return_error_threshold(mut self, percent: u32) -> WorkPolicyBuilder {
        self.return_error_trigger_percent = Some(percent);
        self
    }

    /// Control whether work function will return an log a warning if it completes too quickly.
    ///
    /// Only has any effect if the `logging` feature is selected.
    ///
    /// # Arguments
    /// * `enabled` - if set to false the policy will never return an error. if set to true
    /// the policy will return an error if the proof of work function completes too quickly.
    ///
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::WorkPolicyBuilder;
    /// use std::time::Duration;
    ///
    /// // Create a policy with a target duration of 2.5s that will never return an error.
    /// let policy = WorkPolicyBuilder::default()
    ///                 .log_warning(false)
    ///                 .build(Duration::from_millis(2500));
    ///
    /// # Ok(()) }
    /// ```
    pub fn log_warning(mut self, enabled: bool) -> WorkPolicyBuilder {
        self.log_warning_enabled = Some(enabled);
        self
    }

    /// Control how quickly the proof of work must complete to log a warning.
    ///
    /// Only has any effect if the `logging` feature is selected.
    ///
    /// # Arguments
    /// * `percent` - percentage of target duration below which a warning will be logged.
    ///
    /// ```
    /// # use slowlock::Error;
    /// # fn main() -> Result<(), Error> {
    ///
    /// use slowlock::WorkPolicyBuilder;
    /// use std::time::Duration;
    ///
    /// // Create a policy with a target duration of 2.5s that will log a warning
    /// // if the proof of work function takes less than 82% of the target duration.
    /// let policy = WorkPolicyBuilder::default()
    ///                 .log_warning_threshold(82)
    ///                 .build(Duration::from_millis(2500));
    ///
    /// # Ok(()) }
    /// ```
    pub fn log_warning_threshold(mut self, percent: u32) -> WorkPolicyBuilder {
        self.log_warning_trigger_percent = Some(percent);
        self
    }

    fn make_log_warning_trigger(&self) -> Option<u32> {
        if cfg!(feature = "logging") && self.log_warning_enabled.unwrap_or(true) {
            let trigger = self
                .log_warning_trigger_percent
                .unwrap_or(DEFAULT_LOG_WARNING_TRIGGER_PERCENT);
            Some(trigger)
        } else {
            None
        }
    }

    fn make_return_error_trigger(&self) -> Option<u32> {
        if self.return_error_enabled.unwrap_or(true) {
            let trigger = self
                .return_error_trigger_percent
                .unwrap_or(DEFAULT_RETURN_ERROR_TRIGGER_PERCENT);
            Some(trigger)
        } else {
            None
        }
    }

    pub fn build(self, target_duration: Duration) -> WorkPolicy {
        let return_error_trigger = self.make_return_error_trigger();
        let log_warning_trigger = self.make_log_warning_trigger();

        WorkPolicy {
            target_duration_ms: target_duration.as_millis() as u32,
            log_warning_trigger,
            return_error_trigger,
        }
    }
}

/// Policy controls how the create responds when the work function
/// completes too quickly.
///
///
/// ```
/// # use slowlock::Error;
/// # fn main() -> Result<(), Error> {
///
/// use slowlock::WorkPolicyBuilder;
/// use std::time::Duration;
///
/// // Create a policy with a target duration of 2.5s that will:
/// //  * log a warning if the proof of work function takes less than 75% of the target duration
/// //  * return an error if the proof of work function takes less than 30% of target duration.
/// let policy = WorkPolicyBuilder::default()
///                 .build(Duration::from_millis(2500));
///
///
/// # Ok(()) }
/// ```
pub struct WorkPolicy {
    target_duration_ms: u32,
    log_warning_trigger: Option<u32>,
    return_error_trigger: Option<u32>,
}

impl WorkPolicy {
    // Check an actual duration against the policy
    fn check_duration(&self, actual_duration_ms: u32) -> Result<(), Error> {
        let normalized_duration = (actual_duration_ms * 100) / self.target_duration_ms;

        #[cfg(feature = "logging")]
        if let Some(log_warning_trigger) = self.log_warning_trigger {
            if normalized_duration < log_warning_trigger {
                warn!("Possible security vulnerability; proof of work completed too quickly. Target {}ms, actual {}ms ",
                      self.target_duration_ms,
                      actual_duration_ms
                )
            }
        }

        if let Some(return_error_trigger) = self.return_error_trigger {
            if normalized_duration < return_error_trigger {
                println!("{} {}", return_error_trigger, normalized_duration);
                return Err(Error::ProofOfWorkCompletedTooQuickly {
                    target_duration_ms: self.target_duration_ms,
                    actual_duration_ms,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use aead::Aead;
    use aead::generic_array::GenericArray;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    use crate::{
        Argon2WorkFunction, Argon2WorkFunctionCalibrator, Error, NewSlowAead, WorkPolicy,
        WorkPolicyBuilder,
    };

    const DATA: &[u8] = b"Secret data";
    const PASSWORD1: &[u8] = b"password1";
    const PASSWORD2: &[u8] = b"password2";
    const SALT1: &[u8] = &[0u8; 32];
    const SALT2: &[u8] = &[1u8; 32];

    fn test_work_function() -> Argon2WorkFunction {
        Argon2WorkFunction {
            mem_cost: 4096,
            time_cost: 2,
            lanes: 3,
        }
    }

    fn do_nothing_policy() -> WorkPolicy {
        WorkPolicyBuilder::new()
            .log_warning(false)
            .return_error(false)
            .build(Duration::from_millis(2500))
    }

    #[test]
    fn round_trip_aes_gcm128() {
        let algo: Aes128Gcm = test_work_function()
            .slow_new(b"password1", &[0u8; 32], &do_nothing_policy())
            .unwrap();
        round_trip_aead(algo);
    }

    #[test]
    fn round_trip_aes_gcm256() {
        let algo: Aes256Gcm = test_work_function()
            .slow_new(b"password1", &[0u8; 32], &do_nothing_policy())
            .unwrap();
        round_trip_aead(algo);
    }

    fn round_trip_aead<A>(algo: A)
    where
        A: Aead,
    {
        let data = "message text".as_bytes();
        let nonce = &[0u8; 12];

        let encrypted = algo
            .encrypt(GenericArray::from_slice(nonce), &data[..])
            .unwrap();

        let decrypted = algo
            .decrypt(GenericArray::from_slice(nonce), encrypted.as_slice())
            .unwrap();

        assert_eq!(data, &decrypted);
    }

    #[test]
    fn decrypt_succeeds_if_work_fns_same() {
        let out = round_trip(
            DATA,
            test_work_function(),
            test_work_function(),
            PASSWORD1,
            PASSWORD1,
            SALT1,
            SALT1,
        )
        .unwrap();

        assert_eq!(DATA, out.as_slice());
    }

    #[test]
    fn decrypt_fails_if_password_is_wrong() {
        let err = round_trip(
            DATA,
            test_work_function(),
            test_work_function(),
            PASSWORD1,
            PASSWORD2,
            SALT1,
            SALT1,
        )
        .err()
        .unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_salt_is_wrong() {
        let err = round_trip(
            DATA,
            test_work_function(),
            test_work_function(),
            PASSWORD1,
            PASSWORD1,
            SALT1,
            SALT2,
        )
        .err()
        .unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_mem_cost_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.mem_cost += 1;
        let err = round_trip(
            DATA,
            test_work_function(),
            work_fn2,
            PASSWORD1,
            PASSWORD1,
            SALT1,
            SALT1,
        )
        .err()
        .unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_time_cost_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.time_cost += 1;
        let err = round_trip(
            DATA,
            test_work_function(),
            work_fn2,
            PASSWORD1,
            PASSWORD1,
            SALT1,
            SALT1,
        )
        .err()
        .unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_lanes_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.lanes += 1;
        let err = round_trip(
            DATA,
            test_work_function(),
            work_fn2,
            PASSWORD1,
            PASSWORD1,
            SALT1,
            SALT1,
        )
        .err()
        .unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn algo_gen_fails_if_mem_cost_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.mem_cost = 0;
        let result: Result<Aes256Gcm, Error> =
            work_fn2.slow_new(PASSWORD1, SALT1, &do_nothing_policy());
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("MemoryTooLittle".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_time_cost_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.time_cost = 0;
        let result: Result<Aes256Gcm, Error> =
            work_fn2.slow_new(PASSWORD1, SALT1, &do_nothing_policy());
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("TimeTooSmall".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_lanes_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.lanes = 0;
        let result: Result<Aes256Gcm, Error> =
            work_fn2.slow_new(PASSWORD1, SALT1, &do_nothing_policy());
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("LanesTooFew".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_salt_too_short() {
        let work_fn2 = test_work_function();
        let short_salt = &[0u8; 7];
        let result: Result<Aes256Gcm, Error> =
            work_fn2.slow_new(PASSWORD1, short_salt, &do_nothing_policy());
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("SaltTooShort".to_string()), err);
    }

    fn round_trip(
        data: &[u8],
        work_fn1: Argon2WorkFunction,
        work_fn2: Argon2WorkFunction,
        password1: &[u8],
        password2: &[u8],
        salt1: &[u8],
        salt2: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let algo1: Aes256Gcm = work_fn1.slow_new(&password1, salt1, &do_nothing_policy())?;
        let algo2: Aes256Gcm = work_fn2.slow_new(&password2, salt2, &do_nothing_policy())?;

        let encrypted = algo1
            .encrypt(GenericArray::from_slice(&[0u8; 12]), &data[..])
            .unwrap();

        algo2
            .decrypt(GenericArray::from_slice(&[0u8; 12]), encrypted.as_slice())
            .map_err(|e| e.into())
    }

    #[test]
    fn can_calibrate_with_fixed_num_lanes() {
        let work = Argon2WorkFunctionCalibrator::default()
            .lanes(1)
            .calibrate(Duration::from_millis(100))
            .unwrap();

        assert_eq!(1, work.lanes);
    }

    #[test]
    fn can_calibrate_with_memory_hint_kb() {
        let work1 = Argon2WorkFunctionCalibrator::default()
            .lanes(1)
            .memory_hint_kb(8)
            .calibrate(Duration::from_millis(2000))
            .unwrap();

        let work2 = Argon2WorkFunctionCalibrator::default()
            .lanes(1)
            .memory_hint_kb(1024)
            .calibrate(Duration::from_millis(2000))
            .unwrap();

        // we can't be sure what the final work.mem_cost will be because
        // the calibration function will tune it differently. However work2 should normally
        // have a higher mem_cost than work1.
        assert!(work2.mem_cost > work1.mem_cost)
    }

    #[test]
    fn can_calibrate_with_memory_hint_percent() {
        let work1 = Argon2WorkFunctionCalibrator::default()
            .memory_hint_percent(0.1)
            .calibrate(Duration::from_millis(500))
            .unwrap();

        let work2 = Argon2WorkFunctionCalibrator::default()
            .memory_hint_percent(6.0)
            .calibrate(Duration::from_millis(500))
            .unwrap();

        // we can't be sure what the final work.mem_cost will be because
        // the calibration function will tune it differently. However work2 should normally
        // have a higher mem_cost than work1.
        assert!(work2.mem_cost > work1.mem_cost)
    }

    #[test]
    fn can_calibrate_with_verbose_true() {
        let calibrator = Argon2WorkFunctionCalibrator::default().verbose(true);

        assert_eq!(true, calibrator.verbose);
    }

    #[test]
    fn can_calibrate_with_verbose_false() {
        let calibrator = Argon2WorkFunctionCalibrator::default().verbose(false);

        assert_eq!(false, calibrator.verbose);
    }

    #[test]
    fn work_policy_will_return_an_error_if_and_only_if_actual_duration_below_trigger() {
        let policy = WorkPolicyBuilder::new()
            .return_error(true)
            .return_error_threshold(40)
            .build(Duration::from_millis(1000));

        assert_eq!(
            Some(Error::ProofOfWorkCompletedTooQuickly {
                target_duration_ms: 1000,
                actual_duration_ms: 399,
            }),
            policy.check_duration(399).err()
        );

        assert_eq!(Ok(()), policy.check_duration(401));
    }

    #[cfg(feature = "logging")]
    #[test]
    fn work_policy_will_log_a_warning_if_and_only_if_actual_duration_below_trigger() {
        // have to check logs to see output
        // todo() make test for logging.
        let policy = WorkPolicyBuilder::new()
            .log_warning(true)
            .log_warning_threshold(40)
            .return_error(false)
            .build(Duration::from_millis(1000));

        // this should log a warning
        assert_eq!(Ok(()), policy.check_duration(399));

        // this should not log a warning.
        assert_eq!(Ok(()), policy.check_duration(401));
    }
}
