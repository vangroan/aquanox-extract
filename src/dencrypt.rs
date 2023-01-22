//! PAK file decryption.

pub struct Decrypter {
    revision: usize,
}

impl Decrypter {
    pub fn new(revision: usize) -> Self {
        Self { revision }
    }

    pub fn decrypt(&self, bytes: &[u8; 84]) -> Result<(), ()> {
        todo!()
    }
}
