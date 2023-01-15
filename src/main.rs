extern crate rand;

use hex;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use secp256k1::{Secp256k1, PublicKey};
use tiny_keccak::{Keccak, Hasher};

use std::thread;
use std::time::Instant;
use std::sync::{Arc, Mutex};


fn keccak256(data: [u8; 64]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut result = [0u8; 32];
    keccak.update(&data);
    keccak.finalize(&mut result);
    result
}

fn get_random_key32(rng: &mut ThreadRng) ->  [u8; 32]{
    let mut arr = [0u8; 32];
    rng.fill(&mut arr[..]);
    arr
}

fn generate_random_address(rng: &mut ThreadRng) -> (String, [u8; 32], [u8; 65]) {

    let secp = Secp256k1::new();
    
    
    let private_key= get_random_key32(rng);
    let secret_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let hash = keccak256(public_key.serialize_uncompressed()[1..].try_into().unwrap());

    let addr: [u8; 20] = hash[12..32].try_into().unwrap();
    (hex::encode(addr), private_key, public_key.serialize_uncompressed())

}

const THREADS: u8 = 16;
const GENERATE_COUNT: u32 = 1_000_000;

fn main() {
   
    let mut handles = Vec::new();

    let now = Instant::now();

    let generated_counter = Arc::new(Mutex::new(u128::MIN));
    
    for _t in 0..THREADS {

        let counter = Arc::clone(&generated_counter);

        let handle = thread::spawn(move || {
            let mut rng = thread_rng();

            for i in 0..GENERATE_COUNT {
                
                let (addr, private, public) = generate_random_address(&mut rng);

                if
                    addr.starts_with("deadc0de") || addr.ends_with("deadc0de")
                    || addr.starts_with("d3adc0de") || addr.ends_with("d3adc0de")
                    || ((addr.ends_with("dead") || addr.ends_with("d3ad")) && addr.ends_with("c0de"))
                    || (addr.starts_with("c0de") && (addr.ends_with("dead") || addr.ends_with("d3ad")))
                    || (addr.starts_with("000") && addr.ends_with("0000"))
                    || (addr.starts_with("111") && addr.ends_with("1111"))
                    || (addr.starts_with("222") && addr.ends_with("2222"))
                    || (addr.starts_with("333") && addr.ends_with("3333"))
                    || (addr.starts_with("444") && addr.ends_with("4444"))
                    || (addr.starts_with("555") && addr.ends_with("5555"))
                    || (addr.starts_with("666") && addr.ends_with("6666"))
                    || (addr.starts_with("777") && addr.ends_with("7777"))
                    || (addr.starts_with("888") && addr.ends_with("8888"))
                    || (addr.starts_with("999") && addr.ends_with("9999"))
                    || (addr.starts_with("01234567"))
                    || (addr.starts_with("98765432"))
                    || (addr.ends_with("76543210"))
                    || (addr.ends_with("23456789"))
                {
                    println!("Address 0x{}, Private Key {}, Public Key {}", addr, hex::encode(private), hex::encode(public));
                }

                if i % 5_000 == 0 {
                    let mut count = counter.lock().unwrap();
                    *count += 5_000;

                    let ref_count: &u128 = &count;
                    if ref_count % 500_000 == 0 {
                        let elapsed = now.elapsed();
                        println!("Elapsed: {:.2?}, {}K addr/s, geneated {}K", elapsed, ref_count / elapsed.as_millis(), ref_count / 1000);
                    }
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = now.elapsed();
    let generated_count = Arc::try_unwrap(generated_counter).unwrap().into_inner().unwrap();
    println!("Elapsed: {:.2?}, {}K addr/s", elapsed, generated_count / elapsed.as_millis());

}
