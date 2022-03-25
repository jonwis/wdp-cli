use std::path::PathBuf;

use clap::Parser;
use windows::{
    core::*, Security::Cryptography::DataProtection::*, Security::Cryptography::*,
    Storage::Streams::*, Win32::System::WinRT::*,
};

#[derive(Parser)]
enum Cli {
    /// Encrypt a UTF-8 file and output the encrypted bytes
    Lock {
        /// File to encrypt
        file: String,
    },
    /// Decrypt a file and output the bytes encoded as UTF-8
    Unlock {
        /// File to un-lock
        file: String,
    },
}

unsafe fn as_mut_bytes(buffer: &IBuffer) -> Result<&mut [u8]> {
    let interop = buffer.cast::<IBufferByteAccess>()?;
    let data = interop.Buffer()?;
    Ok(std::slice::from_raw_parts_mut(data, buffer.Length()? as _))
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let provider = DataProtectionProvider::CreateOverloadExplicit("LOCAL=user")?;

    match &args {
        Cli::Lock { file } => {
            let path: PathBuf = file.try_into()?;
            let unprotected = std::fs::read(&path)?;

            println!("Unprotected bytes:");
            println!("{unprotected:02X?}");

            let unprotected = CryptographicBuffer::CreateFromByteArray(&unprotected)?;
            let protected = provider.ProtectAsync(unprotected)?.get()?;
            let protected_bytes = unsafe { as_mut_bytes(&protected)? };
            
            println!("Protected bytes:");
            println!("{protected_bytes:02X?}");

            let output_file = format!("{file}.rust.locked");
            std::fs::write(&output_file, protected_bytes)?;
            println!("Locked as: {output_file}");
        }
        Cli::Unlock { file } => {
            eprintln!("Trying to unlock {file}");
            let path: PathBuf = file.try_into()?;

            let protected_bytes = std::fs::read(&path)?;
            eprintln!("read bytes");

            let protected = CryptographicBuffer::CreateFromByteArray(&protected_bytes)?;
            eprintln!("converted to IBuffer");

            // Error here: Error: ASN1 bad tag value met - trying to decrpyt an existing msal.cache
            let unprotected = provider.UnprotectAsync(protected)?.get()?;
            eprintln!("decrypted content");

            let unprotected_bytes = unsafe { as_mut_bytes(&unprotected)? };
            eprintln!("Got raw bytes");

            let output_file = format!("{file}.rust.unlocked");
            std::fs::write(&output_file, unprotected_bytes)?;
            println!("Unlocked as: {output_file}");
        }
    };

    Ok(())
}
