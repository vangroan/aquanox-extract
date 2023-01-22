use std::ffi::CStr;
use std::fs;
use std::io::{Cursor, Read, SeekFrom};
use std::{error::Error, io::Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use env_logger::Env;
use log::{debug, info};

mod constants;
mod dencrypt;

use crate::constants::*;

const FILE_PATH: &str = r#"dat/pak/aquanox1.pak"#;

/// Header that describes a file inside the PAK.
struct FileInfo {
    /// Byte offset in PAK where header information was retrieved.
    offset: usize,
    /// Decrypted file name.
    name: String,
    /// Decrypted file size in bytes.
    size: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    debug_assert_eq!(KEY_2.len(), KEY_LENGTH);
    debug_assert_eq!(KEY_3.len(), KEY_LENGTH);

    info!("Starting...");

    // Open PAK file
    let pak_file = fs::read(FILE_PATH)?;
    let mut reader = Cursor::new(pak_file.as_slice());

    // Check file header
    {
        let file_header = &pak_file[0..PAK_HEADER.len()];
        debug!("File Header: {:X?}", file_header);

        if file_header != PAK_HEADER {
            let file_header_str = CStr::from_bytes_with_nul(file_header)?;
            return Err(format!("File header does not match 'MASSIVEFILE\0'").into());
        }

        reader.seek(SeekFrom::Current(PAK_HEADER.len() as i64))?;
    }

    let version = reader.read_u16::<LittleEndian>()? as usize;
    let revision = reader.read_u16::<LittleEndian>()? as usize;
    let file_count = reader.read_u32::<LittleEndian>()? as usize;

    info!("Version: {}", version);
    info!("Revision: {}", revision);
    info!("File Count: {}", file_count);

    assert_eq!(
        version, PAK_FORMAT_VERSION,
        "PAK file format must always be Version 3"
    );
    assert!(revision <= 3, "revision must be 0, 1, 2 or 3");

    // Extract copyright
    {
        let buf = &mut [0u8; COPYRIGHT_LEN];
        reader.read_exact(buf)?;

        debug!("Copyright Bytes: {:X?}", buf);

        let part1 = CStr::from_bytes_with_nul(&buf[0..COPYRIGHT_1_LEN])?.to_string_lossy();
        let part2 =
            CStr::from_bytes_with_nul(&buf[COPYRIGHT_1_LEN..COPYRIGHT_1_LEN + COPYRIGHT_2_LEN])?
                .to_string_lossy();

        info!("PAK File Copyright Notice: \"{} {}\"", part1, part2);
    }

    debug_assert_eq!(
        reader.position(),
        FILE_HEAD_START,
        "cursor offset expected to be at first file header"
    );

    let mut file_infos = Vec::<FileInfo>::with_capacity(file_count);

    // Read filenames
    {
        let buf = &mut [0u8; FILE_NAME_LEN];

        for index in 0..file_count {
            // Store the byte offset in the pak where the file header was found.
            // This is only for debugging.
            let offset = reader.position();

            reader.read_exact(buf)?;
            let file_size = reader.read_u32::<LittleEndian>()?;

            // Decrypt Size
            let mut j: usize = 0;
            if revision <= 1 {
                j = index;
            } else if revision == 2 {
                j = index.wrapping_sub(3);
            } else if revision == 3 {
                j = todo!(); // ((-0x1d) - (0x1f * index)) ^ (-0x1b);
            } else {
                unreachable!("unsupported revision");
            }
            j = j % (KEY_LENGTH - 4);
            let el: [u8; FILE_SIZE_LEN] = [KEY_2[j], KEY_2[j + 1], KEY_2[j + 2], KEY_2[j + 3]];
            let el = u32::from_le_bytes(el);
            let file_size = file_size - el;
            debug!("[{}:{:08X}] File size: {} Bytes", index, offset, file_size);

            // Decrypt Filename
            let file_name = {
                let mut file_name = Vec::<u8>::with_capacity(FILE_NAME_LEN);

                let mut j: usize = 0;
                if revision <= 1 {
                    j = index;
                } else if revision == 2 {
                    j = index.wrapping_sub(3);
                } else if revision == 3 {
                    j = todo!(); // ((-0x1d) - (0x1f * index)) ^ (-0x1b);
                } else {
                    unreachable!("unsupported revision");
                }

                for x in 0..FILE_NAME_LEN {
                    let c = buf[x];
                    if c == NULL_BYTE {
                        file_name.push(0);
                        break;
                    }

                    let k = (j + x) & (KEY_LENGTH - 1);
                    let el: u8 = KEY_2[k];

                    file_name.push((c as u8).wrapping_sub(el));
                    // file_name.push(c as u8 - el);
                }

                let filename = CStr::from_bytes_with_nul(&file_name)?;
                debug!(
                    "[{}:{:08X}] Decrypted filename: {:?}",
                    index, offset, filename
                );

                filename.to_str()?.to_owned()
            };

            // if index == 0 {
            //     debug!("[{}] File {}Bytes: {:X?}", index, file_size, buf);
            // }

            file_infos.push(FileInfo {
                offset: offset as usize,
                name: file_name,
                size: file_size as usize,
            });

            buf.fill(0);
        }
    }

    {
        let mut buf = Vec::<u8>::with_capacity(1024 * 1024);

        for file_info in &file_infos {
            // debug!("Offset {:08X}:", reader.position());

            info!("{:08X} {}", file_info.offset, file_info.name);

            buf.resize(file_info.size, 0u8);
            reader.read_exact(&mut buf)?;

            // debug!("File Bytes: {:X?}", buf);

            buf.clear();
        }
    }

    info!("Done.");

    Ok(())
}
