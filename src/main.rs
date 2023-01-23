use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[macro_use]
extern crate anyhow;
use env_logger::Env;
use log::{info, trace};

mod constants;
mod dencrypt;
mod extract;

use crate::constants::*;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    debug_assert_eq!(KEY_2.len() as u32, KEY_LENGTH);
    debug_assert_eq!(KEY_3.len() as u32, KEY_LENGTH);

    info!("Starting...");
    let start_time = Instant::now();

    let mut pak_paths = Vec::new();
    walk_pak_files(AQUANOX_DATA_PATH, &mut pak_paths)?;
    // walk_pak_files(AQUANOX2_DATA_PATH, &mut pak_paths)?;

    for pak_path in pak_paths {
        extract::extract_pak(pak_path)?;
    }

    let elapsed = Instant::now() - start_time;
    info!("Time elapsed: {:.4} seconds", elapsed.as_secs_f64());
    info!("Done.");

    Ok(())
}

/// Walk the given directory's children, and collect every
/// filesystem path that matches the expected PAK file extension.
fn walk_pak_files<P: AsRef<Path>>(path: P, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
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
