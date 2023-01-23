//! PAK file extraction.
use std::ffi::CStr;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, trace};

use crate::constants::*;
use crate::dencrypt::Decrypter;

type ByteCursor<'a> = Cursor<&'a [u8]>;

/// Header that describes a file inside the PAK.
struct FileInfo {
    /// Byte offset in PAK where header information was retrieved.
    offset: u64,
    /// Decrypted file name.
    name: String,
    /// Decrypted file size in bytes.
    size: usize,
}

pub fn extract_pak<P: AsRef<Path>>(pak_path: P) -> Result<()> {
    let pak_path = pak_path.as_ref();
    debug!("extracting {:?}", pak_path.display());

    // Open PAK file
    let pak_file = std::fs::read(pak_path)?;
    let mut reader = Cursor::new(pak_file.as_slice());

    // Validate that the file has the expected header idetifying the format.
    check_file_header(&mut reader, &pak_file)?;

    // Extract values required to make further extraction decisions.
    let version = reader.read_u16::<LittleEndian>()? as usize;
    let revision = reader.read_u16::<LittleEndian>()? as usize;
    let file_count = reader.read_u32::<LittleEndian>()? as usize;

    debug!("version: {}", version);
    debug!("revision: {}", revision);
    debug!("file count: {}", file_count);

    if version != PAK_FORMAT_VERSION {
        return Err(anyhow!("PAK file format must always be version 3: found {}", version));
    }

    if revision > 3 {
        return Err(anyhow!("revision must be 0, 1, 2 or 3"));
    }

    // Skip cursor over copyright section.
    extract_copyright(&mut reader)?;

    debug_assert_eq!(
        reader.position(),
        FILE_HEAD_START,
        "cursor offset expected to be at first file header"
    );

    let file_headers = extract_file_headers(&mut reader, revision, file_count)?;
    debug_assert_eq!(file_count, file_headers.len());

    write_files(&mut reader, &file_headers)?;

    Ok(())
}

fn check_file_header(reader: &mut ByteCursor, pak_bytes: &[u8]) -> Result<()> {
    let file_header = &pak_bytes[0..PAK_HEADER.len()];
    trace!("file header: {:X?}", file_header);

    if file_header != PAK_HEADER {
        return Err(anyhow!("File header does not match 'MASSIVEFILE\0'"));
    }

    reader.seek(SeekFrom::Current(PAK_HEADER.len() as i64))?;

    Ok(())
}

fn extract_copyright(reader: &mut ByteCursor) -> Result<()> {
    let buf = &mut [0u8; COPYRIGHT_LEN];
    reader.read_exact(buf)?;

    trace!("Copyright Bytes: {:X?}", buf);

    let part1 = CStr::from_bytes_with_nul(&buf[0..COPYRIGHT_1_LEN])?.to_string_lossy();
    let part2 = CStr::from_bytes_with_nul(&buf[COPYRIGHT_1_LEN..COPYRIGHT_1_LEN + COPYRIGHT_2_LEN])?.to_string_lossy();

    debug!("PAK File Copyright Notice: \"{} {}\"", part1, part2);

    Ok(())
}

fn extract_file_headers(reader: &mut ByteCursor, revision: usize, file_count: usize) -> Result<Vec<FileInfo>> {
    let mut file_headers = Vec::<FileInfo>::with_capacity(file_count);
    let decrypt = Decrypter::new(revision);

    // Workhorse buffer
    let buf = &mut [0u8; FILE_NAME_LEN];

    for index in 0..file_count as u32 {
        // Store the byte offset in the pak where the file header was found.
        // This is only for debugging.
        let offset = reader.position();

        reader.read_exact(buf)?;
        let file_size = reader.read_u32::<LittleEndian>()?;

        let (file_size, file_name) = decrypt.decrypt(index, &buf, file_size, offset)?;

        file_headers.push(FileInfo {
            offset,
            name: file_name,
            size: file_size,
        });
    }

    Ok(file_headers)
}

fn write_files(reader: &mut ByteCursor, file_headers: &[FileInfo]) -> Result<()> {
    let mut buf = Vec::<u8>::new();
    let mut root = std::env::current_dir()?;
    root.push(OUT_DIR);

    for header in file_headers {
        debug!("{:08X} {}", header.offset, header.name);

        buf.resize(header.size, 0u8);
        reader.read_exact(&mut buf)?;

        // debug!("File Bytes: {:X?}", buf);

        let mut out_path = root.clone();
        out_path.push(&header.name);

        if let Some(parent_path) = out_path.parent() {
            std::fs::create_dir_all(parent_path)?;
        }

        let mut asset_file = std::fs::File::create(out_path)?;
        asset_file.write_all(&buf)?;

        buf.clear();
    }

    Ok(())
}
