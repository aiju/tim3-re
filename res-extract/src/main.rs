use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const DEFAULT_GAME_DIR: &str = "./TIM3/TIMWIN";
const HEADER_SIZE: u64 = 17; // 13-byte filename + 4-byte size

struct ResourceEntry {
    name: String,
    archive: String,
    offset: u32,
    size: u32,
}

/// Parse RESOURCE.MAP and read per-file headers from each archive to build the full index.
fn load_resource_map(game_dir: &Path) -> Result<Vec<ResourceEntry>> {
    let map_path = game_dir.join("RESOURCE.MAP");
    let mut f = File::open(&map_path)
        .with_context(|| format!("cannot open {}", map_path.display()))?;

    // Header: scramble_key[4] + archive_count[2]
    let mut buf4 = [0u8; 4];
    let mut buf2 = [0u8; 2];
    f.read_exact(&mut buf4)?; // scramble key (unused for extraction)
    f.read_exact(&mut buf2)?;
    let archive_count = u16::from_le_bytes(buf2) as usize;

    // Collect (archive_name, vec<offset>) from the MAP
    let mut archives: Vec<(String, Vec<u32>)> = Vec::new();
    for _ in 0..archive_count {
        let mut name_buf = [0u8; 13];
        f.read_exact(&mut name_buf)?;
        let archive_name = cstr(&name_buf);

        f.read_exact(&mut buf2)?;
        let file_count = u16::from_le_bytes(buf2) as usize;

        let mut offsets = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            f.read_exact(&mut buf4)?; // hash (unused)
            f.read_exact(&mut buf4)?;
            offsets.push(u32::from_le_bytes(buf4));
        }
        archives.push((archive_name, offsets));
    }

    // Now read per-file headers from each archive
    let mut entries = Vec::new();
    for (archive_name, offsets) in &archives {
        let archive_path = game_dir.join(archive_name);
        let mut af = match File::open(&archive_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("warning: cannot open {}: {}", archive_path.display(), e);
                continue;
            }
        };

        for &offset in offsets {
            af.seek(SeekFrom::Start(offset as u64))?;
            let mut name_buf = [0u8; 13];
            af.read_exact(&mut name_buf)?;
            let name = cstr(&name_buf);

            af.read_exact(&mut buf4)?;
            let size = u32::from_le_bytes(buf4);

            entries.push(ResourceEntry {
                name,
                archive: archive_name.clone(),
                offset,
                size,
            });
        }
    }

    Ok(entries)
}

/// Extract a null-terminated string from a fixed-size buffer.
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Build a name→entry index (case-insensitive, last entry wins for overlay priority).
fn build_index(entries: &[ResourceEntry]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        map.insert(e.name.to_ascii_uppercase(), i);
    }
    map
}

/// Read the raw data for a resource entry.
fn read_entry_data(game_dir: &Path, entry: &ResourceEntry) -> Result<Vec<u8>> {
    let archive_path = game_dir.join(&entry.archive);
    let mut f = File::open(&archive_path)
        .with_context(|| format!("cannot open {}", archive_path.display()))?;
    f.seek(SeekFrom::Start(entry.offset as u64 + HEADER_SIZE))?;
    let mut data = vec![0u8; entry.size as usize];
    f.read_exact(&mut data)?;
    Ok(data)
}

fn usage() -> ! {
    eprintln!("usage: res-extract [-d game_dir] <command> [args...]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  ls [-l]                  list all files");
    eprintln!("  extract <file> ...       extract files to disk");
    eprintln!("  cat <file> ...           write file contents to stdout");
    eprintln!();
    eprintln!("default game_dir: {DEFAULT_GAME_DIR}");
    std::process::exit(1);
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    // Parse optional -d flag
    let (game_dir, rest) = if args[0] == "-d" {
        if args.len() < 3 {
            usage();
        }
        (PathBuf::from(&args[1]), &args[2..])
    } else {
        (PathBuf::from(DEFAULT_GAME_DIR), &args[..])
    };

    if rest.is_empty() {
        usage();
    }

    let command = &rest[0];
    let file_args = &rest[1..];

    let entries = load_resource_map(&game_dir)?;

    match command.as_str() {
        "ls" => {
            let long = file_args.first().map(|s| s.as_str()) == Some("-l");
            for e in &entries {
                if long {
                    println!("{:<16} {:>8}  {}", e.name, e.size, e.archive);
                } else {
                    println!("{}", e.name);
                }
            }
        }
        "extract" => {
            if file_args.is_empty() {
                bail!("extract requires at least one filename");
            }
            let index = build_index(&entries);
            for name in file_args {
                let key = name.to_ascii_uppercase();
                match index.get(&key) {
                    Some(&i) => {
                        let entry = &entries[i];
                        let data = read_entry_data(&game_dir, entry)?;
                        let mut out = File::create(&entry.name)
                            .with_context(|| format!("cannot create {}", entry.name))?;
                        out.write_all(&data)?;
                        eprintln!("extracted {} ({} bytes)", entry.name, data.len());
                    }
                    None => {
                        eprintln!("warning: {} not found", name);
                    }
                }
            }
        }
        "cat" => {
            if file_args.is_empty() {
                bail!("cat requires at least one filename");
            }
            let index = build_index(&entries);
            let stdout = io::stdout();
            let mut out = BufWriter::new(stdout.lock());
            for name in file_args {
                let key = name.to_ascii_uppercase();
                match index.get(&key) {
                    Some(&i) => {
                        let entry = &entries[i];
                        let data = read_entry_data(&game_dir, entry)?;
                        out.write_all(&data)?;
                    }
                    None => {
                        bail!("{} not found", name);
                    }
                }
            }
            out.flush()?;
        }
        _ => {
            eprintln!("unknown command: {command}");
            usage();
        }
    }

    Ok(())
}
