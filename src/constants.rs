//! File format constants.
#![allow(dead_code)]

/// PAK file extension.
pub const PAK_EXT: &str = "pak";

/// Header of the PAK file.
/// It must always be in the Massive Development format.
pub const PAK_HEADER: &[u8] = b"MASSIVEFILE\0";

/// Version will always be 3
pub const PAK_FORMAT_VERSION: usize = 3;

/// Each file contains the same copyright notice.
///
/// The notice text is made up of two C-strings, so
/// there is a nullbyte at position 60.
pub const COPYRIGHT_LEN: usize = 64;
pub const COPYRIGHT_1_LEN: usize = 60;
pub const COPYRIGHT_2_LEN: usize = 4;

/// Byte offset in PAK where first file header starts.
pub const FILE_HEAD_START: u64 = 0x54;

/// Byte count of encrypted file name ciphertext.
pub const FILE_NAME_LEN: usize = 128;

/// Byte count of file size integer.
pub const FILE_SIZE_LEN: usize = 4; // 32 bits

/// Null byte used to terminate C-strings.
///
/// Equal to '\0'
pub const NULL_BYTE: u8 = 0;

// ----------------------------------------------------------------------------
// Encryption

/// Encryption key used by revisions 0, 1, and 2.
pub const KEY_2: &[u8] = &[
    104, 60, 97, 55, 76, 108, 196, 79, 111, 114, 120, 72, 51, 74, 43, 120, 220, 223, 97, 98, 75,
    110, 41, 106, 115, 108, 110, 68, 111, 74, 68, 102, 104, 68, 51, 55, 102, 85, 103, 79, 111, 214,
    120, 72, 51, 88, 50, 120, 53, 65, 97, 53, 81, 55, 110, 42, 246, 108, 43, 252, 111, 74, 35, 64,
];

/// Encryption key used by revision 3
pub const KEY_3: &[u8] = &[
    112, 74, 75, 106, 51, 119, 52, 68, 111, 77, 59, 39, 68, 39, 83, 68, 54, 100, 107, 110, 108, 61,
    54, 99, 65, 74, 32, 83, 88, 99, 73, 65, 33, 89, 51, 52, 53, 83, 111, 103, 36, 163, 37, 83, 78,
    100, 54, 64, 32, 88, 48, 57, 56, 97, 115, 55, 120, 99, 65, 42, 40, 83, 68, 123,
];

pub const KEY_LENGTH: usize = 64;
