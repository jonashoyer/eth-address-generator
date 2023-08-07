extern crate rand;
extern crate base64;

use base64::Engine;
use hex;
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use rsa::pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePublicKey, DecodePrivateKey};
use secp256k1::{Secp256k1, PublicKey};
use tiny_keccak::{Keccak, Hasher};

use std::thread;
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::str;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::fs;
use std::error::Error;


fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut result = [0u8; 32];
    keccak.update(&data);
    keccak.finalize(&mut result);
    result
}

fn generate_private_key(rng: &mut ThreadRng) ->  [u8; 32]{
    let mut arr = [0u8; 32];
    rng.fill(&mut arr[..]);
    arr
}


fn generate_random_address(rng: &mut ThreadRng) -> ([u8; 20], [u8; 32], [u8; 65]) {
    let secp = Secp256k1::new();
    
    let private_key= generate_private_key(rng);
    let secret_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let hash = keccak256(public_key.serialize_uncompressed()[1..].try_into().unwrap());

    let addr: [u8; 20] = hash[12..32].try_into().unwrap();
    (addr, private_key, public_key.serialize_uncompressed())
}

fn get_address(private_key: [u8; 32]) -> ([u8; 20], [u8; 32], [u8; 65]) {
    let secp = Secp256k1::new();
    
    let secret_key = secp256k1::SecretKey::from_slice(&private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let hash = keccak256(public_key.serialize_uncompressed()[1..].try_into().unwrap());

    let addr: [u8; 20] = hash[12..32].try_into().unwrap();
    (addr, private_key, public_key.serialize_uncompressed())
}

const WORD_LIST: &'static [&'static str] = &[
    "badc0ffee",
    "deadc0ffee",
    "d3adc0ffee",
    "c0ffeec0de",
    "feeldead",
    "feeld3ad",
    "d3adcode",
    "badc0de",
    "acec0de",
    "00000000",
    "11111111",
    "22222222",
    "33333333",
    "44444444",
    "55555555",
    "66666666",
    "77777777",
    "88888888",
    "99999999",
    "0123456789",
    "9876543210",
    "9876543210",
    "0123456789",
];

const HEAD_TAIL_LIST: &'static [&[&'static str; 2]] = &[
  &["c0ffe", "cafe"],
  &["d3ad", "c0de"],
  &["dead", "c0de"],
];

const TAIL_LIST: &'static [&'static str] = &[
  "babe",
  "b00b",
  "c0de",
  "ba11",
  "ba5e",
  "0ace",
  "cafe",
  "dead",
  "dea1",
  "aced",
  "5afe",
  "5eed",
  "feed",
  "face",
  "fade",
  "f00d",
  "beef",
];


fn most_frequent_letter_count(s: &str) -> usize {
    let mut letter_counts = HashMap::new();
    let mut max_count = 0;

    // Count the letters in the string
    for c in s.chars() {
        let count = letter_counts.entry(c).or_insert(0);
        *count += 1;

        if *count > max_count {
            max_count = *count;
        }
    }

    return max_count
}

fn count_leading_zeros(hex_string: &str) -> usize {
    let trimmed = hex_string.trim_start_matches('0');
    hex_string.len() - trimmed.len()
}

fn count_leading(hex_string: &str) -> usize {
    let c = hex_string.chars().next().unwrap();
    let trimmed = hex_string.trim_start_matches(c);
    hex_string.len() - trimmed.len()
}

fn append_to_file(string_to_append: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("generated.txt")?;

    file.write_all(string_to_append.as_bytes())?;

    Ok(())
}

fn is_numeric_string(s: &str) -> bool {
  s.chars().all(|c| c.is_digit(10))
}

fn contains_only_hex_letters(s: &str) -> bool {
  s.chars().all(|c| c >= 'a' && c <= 'f')
}

fn contains_tail(s: &str) -> bool {
  for tail in TAIL_LIST {
    if s.ends_with(tail) {
      return true;
    }
  }

  return false;
}

// fn checksum(address: &[u8; 20]) -> String {
//     let address_hash = keccak256(address);

//     let addr = hex::encode(address); 

//     addr
//         .char_indices()
//         .fold(String::from("0x"), |mut acc, (index, address_char)| {
//             // this cannot fail since it's Keccak256 hashed
//             let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();

//             if n > 7 {
//                 // make char uppercase if ith character is 9..f
//                 acc.push_str(&address_char.to_uppercase().to_string())
//             } else {
//                 // already lowercased
//                 acc.push(address_char)
//             }

//             acc
//         })
// }

fn create_encryption_key() -> (RsaPrivateKey, RsaPublicKey ) {
    let mut rng = thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    (priv_key, pub_key)
}

fn get_encryption_key() -> Option<RsaPublicKey> {

    let contents = match fs::read_to_string("pubkey.pem") {
        Ok(contents) => contents,
        Err(_) => return None,
    };

    let public_key = RsaPublicKey::from_public_key_pem(&contents).unwrap();

    Some(public_key)
}

fn with_encryption(data: &String, pubkey: &Option<RsaPublicKey>) -> String {

    // return if pubkey is none
    if pubkey.is_none() {
        return data.clone();
    }
    
    let mut rng = rand::thread_rng();

    let result = pubkey.clone().unwrap().encrypt(&mut rng, Pkcs1v15Encrypt, &data.as_bytes()).expect("failed to encrypt");

    // return result as base64
    base64::engine::general_purpose::STANDARD.encode(result)
}

fn main() {

    let args: Vec<String> = env::args().collect();

    let mut threads = 8;

    if args.len() > 1 {

        if args[1] == "-c" {

            let (private_key, public_key) = create_encryption_key();
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open("private.pem")
                .unwrap();
            file.write_all(private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .open("pubkey.pem")
                .unwrap();
            file.write_all(public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap().as_bytes()).unwrap();
            

            return;
        }

        if args[1] == "-d" {

            let encoded = args[2].clone();
            let contents = match fs::read_to_string("private.pem") {
                Ok(contents) => contents,
                Err(_) => return,
            };

            let private_key = RsaPrivateKey::from_pkcs8_pem(&contents).unwrap();

            let decoded = base64::engine::general_purpose::STANDARD.decode(&encoded).unwrap();

            let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &decoded).unwrap();

            println!("{}", str::from_utf8(&decrypted).unwrap());

            return;
        }

        // let public_key = RsaPublicKey::from_pkcs1_pem(pem)?;


        if args[1] == "-t" && args.len() > 2 {
            threads = args[2].parse().unwrap_or(8);
        }
    }

    let public_key = get_encryption_key();

    println!("Using {} threads", threads);
    if public_key.is_some() {
        println!("Using Encryption");
    }
   
    let mut handles = Vec::new();

    let now = Instant::now();

    let generated_counter = Arc::new(Mutex::new(u128::MIN));
    let generated_last_update = Arc::new(Mutex::new(Instant::now()));

    for _t in 0..threads {

        let counter = Arc::clone(&generated_counter);
        let last_update = Arc::clone(&generated_last_update);

        let handle = thread::spawn(move || {
            let mut rng = thread_rng();
            let public_key = get_encryption_key();


            // let mut private_key = generate_private_key(&mut rng);

            let mut count = 0;
            loop {

                let (raw_addr, private, _public) = generate_random_address(&mut rng);
                let addr = hex::encode(raw_addr);
                // let (addr, private, public) = get_address(private_key);
                // for byte in private_key.iter_mut().rev() {
                //     if *byte == u8::MAX {
                //         *byte = 0;
                //     } else {
                //         *byte += 1;
                //         break;
                //     }
                // }

                if count_leading_zeros(&addr) > 5 || is_numeric_string(&addr) || contains_only_hex_letters(&addr) || (contains_tail(&addr) && count_leading(&addr) > 3) || (HEAD_TAIL_LIST.iter().any(|&s| (addr.starts_with(s[0]) && addr.ends_with(s[1])))) {
                    // hex::encode(addr)
                    // let checksum_addr = checksum(&raw_addr);
                    println!("Address 0x{}", addr);



                    if let Err(e) = append_to_file(&format!("0x{}: {}\n", addr, with_encryption(&hex::encode(private), &public_key))) {
                        eprintln!("Error appending to file: {}", e);
                    }
                }

                // let freq = most_frequent_letter_count(&addr);

                // if 14 < freq || WORD_LIST.iter().any(|&s| addr.contains(s)) || HEAD_TAIL_LIST.iter().any(|&s| (addr.starts_with(s[0]) && addr.ends_with(s[1])) || (addr.starts_with(s[1]) && addr.ends_with(s[0]))) {
                //     println!("Address 0x{}, Private Key {}, Public Key {}", addr, hex::encode(private), hex::encode(public));
                // }

                count += 1;
                if count >= 50_000 {
                    count = 0;

                    let mut count = counter.lock().unwrap();
                    *count += 50_000;

                    let ref_count: &u128 = &count;
                    if ref_count % 1_000_000 == 0 {

                        
                        let elapsed = now.elapsed();
                        
                        let mut last_count = last_update.lock().unwrap();
                        let interval = last_count.elapsed();
                        *last_count = Instant::now();
                        
                        println!("Elapsed: {:.2?}, {:.2?}K addr/s, [{}M]", elapsed, 1_000_000f64 / interval.as_millis() as f64, *ref_count as f64 / 1_000_000.0);
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
