use slowlock::{Argon2WorkFunction, Error, WorkFunction, SlowLock};
use std::time::{Duration, Instant};
use aes_gcm::Aes256Gcm;
use aead::Aead;
use aead::generic_array::GenericArray;


fn encryption_round_trip_demo(target_duration: Duration) -> Result<(), Error> {

    println!("# Round trip with work function target_duration={:?}", target_duration);

    println!("Calibrating work function (this may take a few seconds):");
    let work = Argon2WorkFunction::calibrate(target_duration)?;
    println!("Calibration complete mem_cost={}, time_cost={}, lanes={}", work.mem_cost, work.time_cost, work.lanes);

    println!();

    let password = "secret password";
    let message = "secret message".as_bytes();

    // Really this needs to be a unique nonce
    let nonce = GenericArray::clone_from_slice(&[0u8; 12]);

    let algo: SlowLock<_, Aes256Gcm, _>  = SlowLock::new(password, work);


    println!("Encrypting message, this should take about {:?} ", target_duration);
    let encrypt_timer = Instant::now();
    let encrypted_message = algo.encrypt(&nonce, message)?;
    println!("Encryption complete (actual time={:?})", encrypt_timer.elapsed());

    println!();

    println!("Decrypting message, this should also take about {:?}", target_duration);
    let decrypt_timer = Instant::now();
    let decrypted_message = algo.decrypt(&nonce, encrypted_message.as_slice())?;
    println!("Decryption complete (actual time={:?})", decrypt_timer.elapsed());


    println!();

    assert_eq!(message, decrypted_message.as_slice());

    Ok(())
}


fn main() {
    encryption_round_trip_demo(Duration::from_millis(500)).unwrap();
    encryption_round_trip_demo(Duration::from_millis(2500)).unwrap();
}