//! PAK file decryption.
use std::ffi::CStr;

use anyhow::Result;
use log::trace;

use crate::constants::*;

pub struct Decrypter {
    revision: usize,
}

impl Decrypter {
    pub fn new(revision: usize) -> Self {
        Self { revision }
    }

    /// Decipher file size and file name.
    ///
    /// # Arguments
    ///
    /// - `file_index` file header's index in the PAK file is used in decryption
    /// - `file_name_cipher` bytes of cipher text extracted from PAK
    /// - `file_size_cipher` bytes of cipher text as integer
    /// - `byte_offset` byte position of file header in file, used to debug printing
    ///
    /// # Returns
    ///
    /// Tuple containing file_size and file_name.
    #[inline]
    pub fn decrypt(
        &self,
        file_index: u32,
        file_name_cipher: &[u8; FILE_NAME_LEN],
        file_size_cipher: u32,
        byte_offset: u64,
    ) -> Result<(usize, String)> {
        if self.revision > PAK_FORMAT_REVISION_MAX {
            return Err(anyhow!("unsupported pak revision: {}", self.revision));
        }

        // Decrypt Size
        let i: u32 = match self.revision {
            0 | 1 => file_index,
            2 => file_index.wrapping_sub(3).wrapping_add(0x68), // index - 3 + 0x68
            3 => todo!("(0x41 + (index * 0x0d)) ^ 0x1b74"),
            _ => unreachable!("unsupported revision"),
        };

        let j = i % (KEY_LENGTH - 4);
        let k_parts: [u8; FILE_SIZE_LEN] = [
            KEY_2[j as usize],
            KEY_2[(j + 1) as usize],
            KEY_2[(j + 2) as usize],
            KEY_2[(j + 3) as usize],
        ];
        let k = u32::from_le_bytes(k_parts);
        let file_size = file_size_cipher - k;
        trace!("[{}:{:08X}] File size: {} Bytes", file_index, byte_offset, file_size);

        // Decrypt File Name
        let file_name = {
            let mut name_bytes = Vec::<u8>::with_capacity(FILE_NAME_LEN);

            let i: u32 = match self.revision {
                0 | 1 => file_index,
                2 => file_index.wrapping_sub(3), // index - 3
                3 => todo!("((-0x1d) - (0x1f * index)) ^ (-0x1b)"),
                _ => unreachable!("unsupported revision"),
            };

            for x in 0..FILE_NAME_LEN {
                let c = file_name_cipher[x];
                if c == NULL_BYTE {
                    name_bytes.push(NULL_BYTE);
                    break;
                }

                let j = (i.wrapping_add(x as u32)) & (KEY_LENGTH - 1); // (i - x) & (0x40 - 1)
                let k: u8 = KEY_2[j as usize];

                name_bytes.push((c as u8).wrapping_sub(k)); // c - k
            }

            let name_str = CStr::from_bytes_with_nul(&name_bytes)?;
            trace!(
                "[{}:{:08X}] Decrypted filename: {:?}",
                file_index,
                byte_offset,
                name_str
            );

            name_str.to_str()?.to_owned()
        };

        Ok((file_size as usize, file_name))
    }
}
