use std::time::{Duration, Instant};

use aead::generic_array::GenericArray;
use aead::Aead;
use aes_gcm::Aes256Gcm;

use slowlock::{Argon2WorkFunctionCalibrator, Error, NewSlowAead, WorkPolicyBuilder};

fn encryption_round_trip_demo(target_duration: Duration) -> Result<(), Error> {
    println!(
        "# Round trip with work function target_duration={:?}",
        target_duration
    );

    println!("Calibrating work function (this may take a few seconds):");

    let work = Argon2WorkFunctionCalibrator::new()
        .verbose(true)
        .calibrate(target_duration)?;

    let policy = WorkPolicyBuilder::new().build(target_duration);

    println!("Calibration complete");

    println!();

    let password = "secret password";
    let message = "secret message".as_bytes();

    // Really this needs to be a unique nonce
    let nonce = GenericArray::clone_from_slice(&[0u8; 12]);
    let salt = &[0u8; 32];

    println!(
        "Encrypting message, this should take about {:?} ",
        target_duration
    );
    let encrypt_timer = Instant::now();
    let algo: Aes256Gcm = work.slow_new(password.as_bytes(), salt, &policy)?;
    let encrypted_message = algo.encrypt(&nonce, message)?;
    println!(
        "Encryption complete (actual time={:?})",
        encrypt_timer.elapsed()
    );

    println!();

    println!(
        "Decrypting message, this should also take about {:?}",
        target_duration
    );
    let decrypt_timer = Instant::now();
    let algo: Aes256Gcm = work.slow_new(password.as_bytes(), salt, &policy)?;
    let decrypted_message = algo.decrypt(&nonce, encrypted_message.as_slice())?;
    println!(
        "Decryption complete (actual time={:?})",
        decrypt_timer.elapsed()
    );

    println!();

    assert_eq!(message, decrypted_message.as_slice());

    Ok(())
}

fn main() {
    #[cfg(feature = "logging")]
    {
        simple_logger::SimpleLogger::new().init().unwrap();
    }

    encryption_round_trip_demo(Duration::from_millis(100)).unwrap();
    encryption_round_trip_demo(Duration::from_millis(500)).unwrap();
    encryption_round_trip_demo(Duration::from_millis(2500)).unwrap();
}
