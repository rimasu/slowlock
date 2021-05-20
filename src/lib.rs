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
//! To be useful the proof of work function must take a reasonable amount of time/effort
//! to complete. This crates provides a [Argon2WorkFunctionCalibrator] with (I hope) reasonable
//! defaults that can be used to create work functions with variable target durations.
//!
//! The other part of this is detecting when a previously reasonable work function is now
//! completing too quickly. Unless occasionally re-calibrated, we should expect this to happen
//! over time as machine performance improves.
//!
//! This crate has X ways to to detect work functions that are too weak.
//!
//! 1) If logging is enabled and the work function completes in less than two thirds the expected
//! time a warning is logged.
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
//! is long and may be stored be in some trusted hardware store.  This secret means that an attacker
//! in possession of the hashed password and salt still has a missing component.
//!
//! In this library Argon2 is not being used to verify password, but as a proof of work
//! function. So although the salt is stored, the hashed password is never exposed (it is
//! directly used as the `cipher_key`). This means there is limited risk of the attacker gaining access
//! to the `salt` and hashed password.
//!
use std::time::{Duration, Instant};

use aead::generic_array::{ArrayLength, GenericArray};
use aead::generic_array::typenum::consts::U32;
use aead::NewAead;
#[cfg(feature = "logging")]
use log::{info, warn};
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
    ProofOfWorkCompletedTooQuickly,
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
    /// * `policy` - a optional policy that will control behaviour if the work function completes too quickly.
    /// If policy is None, then no action is taken.
    ///
    /// # Errors
    ///
    /// Will return an error if proof of work functions parameters are not valid.
    ///
    fn slow_new(&self, password: &[u8], salt: &[u8], policy: Option<&WorkPolicy>) -> Result<A, Error>;
}

/// NewSlowAead is implemented for anything that implements a work function.
impl<W, A> NewSlowAead<A> for W
    where
        W: WorkFunction,
        A: NewAead,
{

    fn slow_new(&self, password: &[u8], salt: &[u8], policy: Option<&WorkPolicy>) -> Result<A, Error> {

        let now = Instant::now();
        let key = self.make_cipher_key(password, salt)?;
        let work_duration = now.elapsed();

        Ok(A::new(&key))
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
    /// * `password` - secret data supplied by user
    /// * `salt` - pseudo-random data stored with secured data to ensure that users with same
    /// `password` end up with different `cipher_key`s.
    ///
    fn make_cipher_key<K>(&self, password: &[u8], salt: &[u8]) -> Result<GenericArray<u8, K>, Error>
        where
            K: ArrayLength<u8>;
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
/// let key: GenericArray<u8, U32> = work_fn.make_cipher_key(password, &salt)?;
///
/// let expected_key = &hex!("a2867fb2a2ddb384cba4f382f5db48b36066cbcb755ed7f07aeabef1f98fbf54");
/// assert_eq!(expected_key, key.as_slice());
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
    fn make_cipher_key<K>(&self, password: &[u8], salt: &[u8]) -> Result<GenericArray<u8, K>, Error>
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

        argon2::hash_raw(password, salt, &config)
            .map_err(|e| e.into())
            .map(|h| GenericArray::clone_from_slice(&h))
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
                    break
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
        let _key: GenericArray<u8, U32> = self.make_cipher_key(&[0u8; 32], &[0u8; 32])?;
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
///
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
/// let algo: Aes256Gcm = work_fn.slow_new(b"password", &[0u8; 32], Some(&policy))?;
///
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
    /// Only availble if the `logging` feature is selected.
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
    #[cfg(feature = "logging")]
    pub fn log_warning(mut self, enabled: bool) -> WorkPolicyBuilder {
        self.log_warning_enabled = Some(enabled);
        self
    }


    /// Control how quickly the proof of work must complete to log a warning.
    ///
    /// Only availble if the `logging` feature is selected.
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
    #[cfg(feature = "logging")]
    pub fn log_warning_threshold(mut self, percent: u32) -> WorkPolicyBuilder {
        self.log_warning_trigger_percent = Some(percent);
        self
    }


    fn make_log_warning_trigger(&self) -> Option<u32> {
        if cfg!(feature = "logging") && self.log_warning_enabled.unwrap_or(true) {
            let trigger = self.log_warning_trigger_percent
                .unwrap_or(DEFAULT_LOG_WARNING_TRIGGER_PERCENT);
            Some(trigger)
        } else {
            None
        }
    }

    fn make_return_error_trigger(&self) -> Option<u32> {
        if self.return_error_enabled.unwrap_or(true) {
            let trigger = self.return_error_trigger_percent
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


#[cfg(test)]
mod test {
    use std::time::Duration;

    use aead::Aead;
    use aead::generic_array::GenericArray;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    use crate::{Argon2WorkFunction, Argon2WorkFunctionCalibrator, Error, NewSlowAead};

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

    #[test]
    fn round_trip_aes_gcm128() {
        let algo: Aes128Gcm = test_work_function().slow_new(b"password1", &[0u8; 32], None).unwrap();
        round_trip_aead(algo);
    }

    #[test]
    fn round_trip_aes_gcm256() {
        let algo: Aes256Gcm = test_work_function().slow_new(b"password1", &[0u8; 32], None).unwrap();
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
        let out = round_trip(DATA,
                             test_work_function(),
                             test_work_function(),
                             PASSWORD1,
                             PASSWORD1,
                             SALT1,
                             SALT1).unwrap();

        assert_eq!(DATA, out.as_slice());
    }

    #[test]
    fn decrypt_fails_if_password_is_wrong() {
        let err = round_trip(DATA,
                             test_work_function(),
                             test_work_function(),
                             PASSWORD1,
                             PASSWORD2,
                             SALT1,
                             SALT1).err().unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_salt_is_wrong() {
        let err = round_trip(DATA,
                             test_work_function(),
                             test_work_function(),
                             PASSWORD1,
                             PASSWORD1,
                             SALT1,
                             SALT2).err().unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_mem_cost_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.mem_cost += 1;
        let err = round_trip(DATA,
                             test_work_function(),
                             work_fn2,
                             PASSWORD1,
                             PASSWORD1,
                             SALT1,
                             SALT1).err().unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_time_cost_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.time_cost += 1;
        let err = round_trip(DATA,
                             test_work_function(),
                             work_fn2,
                             PASSWORD1,
                             PASSWORD1,
                             SALT1,
                             SALT1).err().unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn decrypt_fails_if_lanes_is_wrong() {
        let mut work_fn2 = test_work_function();
        work_fn2.lanes += 1;
        let err = round_trip(DATA,
                             test_work_function(),
                             work_fn2,
                             PASSWORD1,
                             PASSWORD1,
                             SALT1,
                             SALT1).err().unwrap();

        assert_eq!(Error::AeadOperationFailed, err);
    }

    #[test]
    fn algo_gen_fails_if_mem_cost_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.mem_cost = 0;
        let result: Result<Aes256Gcm, Error> = work_fn2.slow_new(PASSWORD1, SALT1, None);
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("MemoryTooLittle".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_time_cost_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.time_cost = 0;
        let result: Result<Aes256Gcm, Error> = work_fn2.slow_new(PASSWORD1, SALT1, None);
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("TimeTooSmall".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_lanes_too_low() {
        let mut work_fn2 = test_work_function();
        work_fn2.lanes = 0;
        let result: Result<Aes256Gcm, Error> = work_fn2.slow_new(PASSWORD1, SALT1, None);
        let err = result.err().unwrap();

        assert_eq!(Error::ProofOfWorkFailed("LanesTooFew".to_string()), err);
    }

    #[test]
    fn algo_gen_fails_if_salt_too_short() {
        let work_fn2 = test_work_function();
        let short_salt = &[0u8; 7];
        let result: Result<Aes256Gcm, Error> = work_fn2.slow_new(PASSWORD1, short_salt, None);
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
        let algo1: Aes256Gcm = work_fn1.slow_new(&password1, salt1, None)?;
        let algo2: Aes256Gcm = work_fn2.slow_new(&password2, salt2, None)?;

        let encrypted = algo1
            .encrypt(GenericArray::from_slice(&[0u8; 12]), &data[..])
            .unwrap();

        algo2.decrypt(GenericArray::from_slice(&[0u8; 12]), encrypted.as_slice())
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
        let calibrator = Argon2WorkFunctionCalibrator::default()
            .verbose(true);

        assert_eq!(true, calibrator.verbose);
    }

    #[test]
    fn can_calibrate_with_verbose_false() {
        let calibrator = Argon2WorkFunctionCalibrator::default()
            .verbose(false);

        assert_eq!(false, calibrator.verbose);
    }
}
