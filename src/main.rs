use std::{io::BufRead, time::SystemTime};

use sequoia_openpgp::{
    crypto::Password,
    packet::{
        key::{PrimaryRole, SecretParts, SubordinateRole},
        prelude::Key4,
        signature::SignatureBuilder,
        Key, UserID,
    },
    serialize::Marshal,
    types::{
        CompressionAlgorithm, Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm,
    },
    Cert, Packet,
};
use zeroize::Zeroizing;
fn main() {
    let stdin = &mut std::io::stdin().lock();
    let buf = &mut *Zeroizing::new(String::with_capacity(1024));
    let [primary_key, encryption_key] = &mut **Box::new(Zeroizing::new([[0u8; 32]; 2]));
    eprintln!("Enter Primary (Signing, Certification) key mnemonic:");
    read_mnemonic(buf, stdin, primary_key);
    eprintln!("Enter Encryption subkey mnemonic:");
    read_mnemonic(buf, stdin, encryption_key);
    let password = read_password(buf, stdin);
    let userid = read_userid(buf, stdin);
    let timestamp = read_timestamp(buf, stdin);
    let cert = generate(
        primary_key,
        encryption_key,
        password.as_ref(),
        userid,
        timestamp,
    )
    .unwrap();

    let mut out_file = std::fs::File::create("test.priv").unwrap();
    cert.as_tsk() /* .armored() */
        .serialize(&mut out_file)
        .unwrap();
}

fn read_mnemonic(buf: &mut String, stdin: &mut std::io::StdinLock, out: &mut [u8; 32]) {
    loop {
        buf.clear();
        stdin.read_line(buf).unwrap();
        match bip39::Mnemonic::from_phrase(buf, Default::default()) {
            Ok(mnem) => {
                let entropy = mnem.entropy();
                match <&[u8; 32]>::try_from(entropy) {
                    Ok(bytes) => {
                        *out = *bytes;
                        break;
                    }
                    Err(_) => {
                        let len = entropy.len();
                        eprintln!("Size error: expected 24 words (32 bytes), got {len} bytes",);
                    }
                }
            }
            Err(err) => {
                eprintln!("Mnemonic error: {err}. Please try again.");
            }
        };
    }
}
fn read_password(buf: &mut String, stdin: &mut std::io::StdinLock) -> Option<Password> {
    buf.clear();
    eprint!("Enter passphrase to encrypt private keys (or nothing): ");
    stdin.read_line(buf).unwrap();
    if buf.trim().is_empty() {
        eprintln!("No passphrase supplied, not encrypting private keys!");
        None
    } else {
        Some(Password::from(buf.trim_end()))
    }
}
fn read_userid(buf: &mut String, stdin: &mut std::io::StdinLock) -> UserID {
    buf.clear();
    eprint!("Enter username (or nothing): ");
    let name_len = stdin.read_line(buf).unwrap();
    eprint!("Enter email: ");
    loop {
        stdin.read_line(buf).unwrap();
        let name = buf[..name_len].trim();
        match UserID::from_address(
            (!name.is_empty()).then_some(name),
            // see http://web.archive.org/web/20201020082313/https://debian-administration.org/users/dkg/weblog/97
            None,
            buf[name_len..].trim(),
        ) {
            Ok(userid) => break userid,
            Err(err) => {
                eprintln!("User ID error \"{err}\", probably bad email? Try again.");
                buf.truncate(name_len);
            }
        }
    }
}
fn read_timestamp(buf: &mut String, stdin: &mut std::io::StdinLock) -> SystemTime {
    eprintln!("Enter a timestamp in RFC 3339 (ISO 8601) format like 1996-12-19T16:39:57+02:00 (or nothing):");
    loop {
        buf.clear();
        stdin.read_line(buf).unwrap();
        let text = buf.trim();
        if text.is_empty() {
            let now = chrono::Local::now();
            eprintln!("Using current timestamp: {now}");
            break now.into();
        }
        match chrono::DateTime::parse_from_rfc3339(text) {
            Ok(timestamp) => break timestamp.into(),
            Err(err) => {
                eprintln!("Invalid timestamp: {err}. Try again.")
            }
        }
    }
}

fn generate(
    primary_key: &[u8; 32],
    encryption_key: &mut [u8; 32],
    password: Option<&Password>,
    userid: UserID,
    timestamp: SystemTime,
) -> sequoia_openpgp::Result<Cert> {
    trim_cv25519_key(encryption_key);
    let mut primary_key = Key::from(Key4::<SecretParts, PrimaryRole>::import_secret_ed25519(
        primary_key,
        timestamp,
    )?);
    let mut primary_keypair = primary_key.clone().into_keypair()?;
    let primary_key_signature = SignatureBuilder::new(SignatureType::DirectKey)
        .set_features(Features::sequoia())?
        .set_signature_creation_time(timestamp)?
        .set_key_flags(KeyFlags::empty().set_certification().set_signing())?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES192,
            SymmetricAlgorithm::AES128,
        ])?
        .set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA256,
        ])?
        .set_preferred_compression_algorithms(vec![
            CompressionAlgorithm::Zlib,
            CompressionAlgorithm::BZip2,
            CompressionAlgorithm::Zip,
        ])?
        .sign_direct_key(&mut primary_keypair, None)?;
    let userid_signature = SignatureBuilder::from(primary_key_signature.clone())
        .set_type(SignatureType::PositiveCertification)
        .set_signature_creation_time(timestamp)?
        .set_primary_userid(true)?
        .sign_userid_binding(&mut primary_keypair, None, &userid)?;
    let mut encryption_key =
        Key::from(Key4::<SecretParts, SubordinateRole>::import_secret_cv25519(
            encryption_key,
            HashAlgorithm::SHA512,
            SymmetricAlgorithm::AES256,
            timestamp,
        )?);
    let encryption_key_signature = SignatureBuilder::new(SignatureType::SubkeyBinding)
        // .set_features(Features::sequoia())?
        .set_signature_creation_time(timestamp)?
        .set_key_flags(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
        )?
        .sign_subkey_binding(&mut primary_keypair, None, &encryption_key)?;
    if let Some(password) = password {
        primary_key = primary_key.encrypt_secret(password).unwrap();
        encryption_key = encryption_key.encrypt_secret(password).unwrap();
    }
    let packets = [
        Packet::from(primary_key),
        Packet::from(primary_key_signature),
        Packet::from(userid),
        Packet::from(userid_signature),
        Packet::from(encryption_key),
        Packet::from(encryption_key_signature),
    ];
    Cert::from_packets(packets.into_iter())
}

/// Destroy the randomness to make it fit.
fn trim_cv25519_key([head, .., tail]: &mut [u8; 32]) {
    // Curve25519 Paper, Sec. 3:
    // A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first
    // byte, clear bit 7 of the last byte, and set bit 6 of the last byte.
    *head &= 0b01111_1000;
    *tail &= !0b1000_0000;
    *tail |= 0b00100_0000;
}
