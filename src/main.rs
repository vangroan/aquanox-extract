use std::error::Error;
use std::ffi::CStr;
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use byteorder::{LittleEndian, ReadBytesExt};
use env_logger::Env;
use log::{debug, info, trace};

mod constants;
mod dencrypt;

use crate::constants::*;

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
    let start_time = Instant::now();

    let mut pak_paths = Vec::new();
    walk_pak_files(AQUANOX_DATA_PATH, &mut pak_paths)?;

    for pak_path in pak_paths {
        process_pak(pak_path)?;
    }

    let elapsed = Instant::now() - start_time;
    info!("Time elapsed: {:.4} seconds", elapsed.as_secs_f64());
    info!("Done.");

    Ok(())
}

/// Walk the given directory's children, and collect every
/// filesystem path that matches the expected PAK file extension.
fn walk_pak_files<P: AsRef<Path>>(path: P, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    let walker = walkdir::WalkDir::new(path);

    for entry in walker {
        let dir_entry = entry?;
        let path = dir_entry.path();
        let file_name = dir_entry.file_name().to_str().unwrap();
        if file_name.ends_with(PAK_EXT) && path.is_file() {
            info!("Found {}", path.display());
            out.push(path.to_owned());
        } else {
            trace!("Found {}", path.display());
        }
    }

    Ok(())
}

fn process_pak<P: AsRef<Path>>(pak_path: P) -> Result<(), Box<dyn Error>> {
    let pak_path = pak_path.as_ref();
    trace!("Processing {:?}", pak_path.display());

    // Open PAK file
    let pak_file = fs::read(pak_path)?;
    let mut reader = Cursor::new(pak_file.as_slice());

    // Check file header
    {
        let file_header = &pak_file[0..PAK_HEADER.len()];
        trace!("File Header: {:X?}", file_header);

        if file_header != PAK_HEADER {
            let file_header_str = CStr::from_bytes_with_nul(file_header)?;
            return Err(format!("File header does not match 'MASSIVEFILE\0'").into());
        }

        reader.seek(SeekFrom::Current(PAK_HEADER.len() as i64))?;
    }

    let version = reader.read_u16::<LittleEndian>()? as usize;
    let revision = reader.read_u16::<LittleEndian>()? as usize;
    let file_count = reader.read_u32::<LittleEndian>()? as usize;

    debug!("Version: {}", version);
    debug!("Revision: {}", revision);
    debug!("File Count: {}", file_count);

    assert_eq!(
        version, PAK_FORMAT_VERSION,
        "PAK file format must always be Version 3"
    );
    assert!(revision <= 3, "revision must be 0, 1, 2 or 3");

    // Extract copyright
    {
        let buf = &mut [0u8; COPYRIGHT_LEN];
        reader.read_exact(buf)?;

        trace!("Copyright Bytes: {:X?}", buf);

        let part1 = CStr::from_bytes_with_nul(&buf[0..COPYRIGHT_1_LEN])?.to_string_lossy();
        let part2 =
            CStr::from_bytes_with_nul(&buf[COPYRIGHT_1_LEN..COPYRIGHT_1_LEN + COPYRIGHT_2_LEN])?
                .to_string_lossy();

        debug!("PAK File Copyright Notice: \"{} {}\"", part1, part2);
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
            let i: usize = match revision {
                0 | 1 => index,
                2 => index.wrapping_sub(3), // index - 3
                3 => todo!("((-0x1d) - (0x1f * index)) ^ (-0x1b)"),
                _ => unreachable!("unsupported revision"),
            };

            let j = i % (KEY_LENGTH - 4);
            let k_parts: [u8; FILE_SIZE_LEN] = [KEY_2[j], KEY_2[j + 1], KEY_2[j + 2], KEY_2[j + 3]];
            let k = u32::from_le_bytes(k_parts);
            let file_size = file_size - k;
            trace!("[{}:{:08X}] File size: {} Bytes", index, offset, file_size);

            // Decrypt Filename
            let file_name = {
                let mut file_name = Vec::<u8>::with_capacity(FILE_NAME_LEN);

                for x in 0..FILE_NAME_LEN {
                    let c = buf[x];
                    if c == NULL_BYTE {
                        file_name.push(0);
                        break;
                    }

                    let j = (i + x) & (KEY_LENGTH - 1);
                    let k: u8 = KEY_2[j];

                    file_name.push((c as u8).wrapping_sub(k)); // c - k
                }

                let filename = CStr::from_bytes_with_nul(&file_name)?;
                trace!(
                    "[{}:{:08X}] Decrypted filename: {:?}",
                    index,
                    offset,
                    filename
                );

                filename.to_str()?.to_owned()
            };

            file_infos.push(FileInfo {
                offset: offset as usize,
                name: file_name,
                size: file_size as usize,
            });

            buf.fill(0);
        }
    }

    {
        let mut buf = Vec::<u8>::new();
        let mut root = std::env::current_dir()?;
        root.push(OUT_DIR);

        for file_info in &file_infos {
            // debug!("Offset {:08X}:", reader.position());
            debug!("{:08X} {}", file_info.offset, file_info.name);

            buf.resize(file_info.size, 0u8);
            reader.read_exact(&mut buf)?;

            // debug!("File Bytes: {:X?}", buf);

            let mut out_path = root.clone();
            out_path.push(&file_info.name);

            if let Some(parent_path) = out_path.parent() {
                fs::create_dir_all(parent_path)?;
            }

            let mut asset_file = std::fs::File::create(out_path)?;
            asset_file.write_all(&buf)?;

            buf.clear();
        }

        Ok(())
    }
}
