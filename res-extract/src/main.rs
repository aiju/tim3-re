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

// --- ITF file format parsing ---

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_i16(data: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Read a null-terminated string from data at offset, return (string, bytes consumed including null).
fn read_cstring(data: &[u8], off: usize) -> (String, usize) {
    let end = data[off..].iter().position(|&b| b == 0).unwrap_or(data.len() - off);
    let s = String::from_utf8_lossy(&data[off..off + end]).into_owned();
    (s, end + 1)
}

struct ItfControl {
    control_type: u16,
    id: u16,
    cursor_type: i16,
    x: i16,
    y: i16,
    width: u16,
    height: u16,
    anim_flag: u16,
    event_id: u16,
    offset_x: i16,
    offset_y: i16,
    button_ext: Option<ButtonExtData>,
}

struct ButtonExtData {
    active_renderer: i16,
    active_color: i16,
    renderer_id: i16,
    text_x: i16,
    text_y: i16,
    text_w: i16,
    text_h: i16,
    text_flags: i16,
    text_color: i16,
}

struct ItfTag {
    id: u16,
    name: String,
}

struct ItfFile {
    version: u16,
    animation: String,
    controls: Vec<ItfControl>,
    tags: Vec<ItfTag>,
}

fn parse_itf(data: &[u8]) -> Result<ItfFile> {
    // Parse chunks - find ITF: and TAG: chunks
    let mut itf_chunk: Option<(usize, usize)> = None; // (data_start, data_len)
    let mut tag_chunk: Option<(usize, usize)> = None;
    let mut pos = 0;
    while pos + 8 <= data.len() {
        let tag = &data[pos..pos + 4];
        let size = read_u32(data, pos + 4) as usize;
        let data_start = pos + 8;
        if data_start + size > data.len() {
            break;
        }
        match tag {
            b"ITF:" => itf_chunk = Some((data_start, size)),
            b"TAG:" => tag_chunk = Some((data_start, size)),
            _ => {}
        }
        pos = data_start + size;
    }

    let (itf_start, _itf_size) = itf_chunk.ok_or_else(|| anyhow::anyhow!("no ITF: chunk found"))?;

    // Parse ITF header
    let mut off = itf_start;
    if data[off] != b'T' || data[off + 1] != b'B' {
        bail!("bad ITF magic (expected TB)");
    }
    off += 2;

    let version = read_u16(data, off);
    off += 2;

    let (animation, name_len) = read_cstring(data, off);
    off += name_len;

    let count = read_u16(data, off) as usize;
    off += 2;

    // Prescan: count * u16 control types (used for memory allocation in game)
    let mut prescan_types = Vec::with_capacity(count);
    for _ in 0..count {
        prescan_types.push(read_u16(data, off));
        off += 2;
    }

    // Parse controls
    let mut controls = Vec::with_capacity(count);
    for i in 0..count {
        let control_type = read_u16(data, off); off += 2;
        let id = read_u16(data, off); off += 2;
        let cursor_type = read_i16(data, off); off += 2;
        let x = read_i16(data, off); off += 2;
        let y = read_i16(data, off); off += 2;
        let width = read_u16(data, off); off += 2;
        let height = read_u16(data, off); off += 2;

        let anim_flag = if version >= 0x44f {
            let v = read_u16(data, off); off += 2; v
        } else {
            1
        };

        let event_id = read_u16(data, off); off += 2;

        let (offset_x, offset_y) = if version >= 0x44e {
            let ox = read_i16(data, off); off += 2;
            let oy = read_i16(data, off); off += 2;
            (ox, oy)
        } else {
            (-x, -y)
        };

        let button_ext = if prescan_types[i] == 4 && version >= 0x44d {
            let active_renderer = read_i16(data, off); off += 2;
            let active_color = read_i16(data, off); off += 2;
            let renderer_id = read_i16(data, off); off += 2;
            let text_x = read_i16(data, off); off += 2;
            let text_y = read_i16(data, off); off += 2;
            let text_w = read_i16(data, off); off += 2;
            let text_h = read_i16(data, off); off += 2;
            let text_flags = read_i16(data, off); off += 2;
            let text_color = read_i16(data, off); off += 2;
            Some(ButtonExtData {
                active_renderer, active_color, renderer_id,
                text_x, text_y, text_w, text_h, text_flags, text_color,
            })
        } else {
            None
        };

        controls.push(ItfControl {
            control_type, id, cursor_type, x, y, width, height,
            anim_flag, event_id, offset_x, offset_y, button_ext,
        });
    }

    // Parse TAG chunk
    let mut tags = Vec::new();
    if let Some((tag_start, tag_size)) = tag_chunk {
        let mut toff = tag_start;
        let tag_end = tag_start + tag_size;
        if toff + 2 <= tag_end {
            let tag_count = read_u16(data, toff) as usize;
            toff += 2;
            for _ in 0..tag_count {
                if toff + 2 > tag_end { break; }
                let id = read_u16(data, toff); toff += 2;
                let (name, name_len) = read_cstring(data, toff);
                toff += name_len;
                tags.push(ItfTag { id, name });
            }
        }
    }

    Ok(ItfFile { version, animation, controls, tags })
}

const CONTROL_TYPE_NAMES: &[&str] = &[
    "static",       // 0
    "pushButton",   // 1
    "clickButton",  // 2
    "toggle",       // 3
    "textEdit",     // 4
    "repeatButton", // 5
    "null",         // 6
];

fn print_itf(itf: &ItfFile) {
    let tag_map: HashMap<u16, &str> = itf.tags.iter().map(|t| (t.id, t.name.as_str())).collect();

    println!("Version: 0x{:04x}", itf.version);
    println!("Animation: {}", itf.animation);
    println!("Controls: {}", itf.controls.len());
    if !itf.tags.is_empty() {
        println!("Tags: {}", itf.tags.len());
    }
    println!();

    for (i, c) in itf.controls.iter().enumerate() {
        let type_name = CONTROL_TYPE_NAMES.get(c.control_type as usize)
            .unwrap_or(&"???");
        let tag_name = tag_map.get(&c.id).copied().unwrap_or("");

        println!("[{:2}] {} (type {})", i, type_name, c.control_type);
        if !tag_name.is_empty() {
            println!("     name: {}", tag_name);
        }
        println!("     id: 0x{:04x}  cursor: {}", c.id, c.cursor_type);
        println!("     pos: ({}, {})  size: {}x{}", c.x, c.y, c.width, c.height);
        if c.anim_flag != 0 || c.event_id != 0 {
            println!("     anim_flag: {}  event: {}", c.anim_flag, c.event_id);
        }
        if c.offset_x != 0 || c.offset_y != 0 {
            println!("     offset: ({}, {})", c.offset_x, c.offset_y);
        }
        if let Some(ref ext) = c.button_ext {
            println!("     text: pos=({},{}) size={}x{} renderer={} color={} flags=0x{:x}",
                ext.text_x, ext.text_y, ext.text_w, ext.text_h,
                ext.renderer_id, ext.text_color, ext.text_flags);
            println!("     active: renderer={} color={}", ext.active_renderer, ext.active_color);
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: res-extract [-d game_dir] <command> [args...]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  ls [-l]                  list all files");
    eprintln!("  extract <file> ...       extract files to disk");
    eprintln!("  cat <file> ...           write file contents to stdout");
    eprintln!("  itf <file> ...           parse and display ITF interface files");
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
        "itf" => {
            if file_args.is_empty() {
                bail!("itf requires at least one filename");
            }
            let index = build_index(&entries);
            for (fi, name) in file_args.iter().enumerate() {
                if fi > 0 { println!(); }
                let key = name.to_ascii_uppercase();
                match index.get(&key) {
                    Some(&i) => {
                        let entry = &entries[i];
                        let data = read_entry_data(&game_dir, entry)?;
                        println!("=== {} ===", entry.name);
                        let itf = parse_itf(&data)
                            .with_context(|| format!("parsing {}", entry.name))?;
                        print_itf(&itf);
                    }
                    None => {
                        bail!("{} not found", name);
                    }
                }
            }
        }
        _ => {
            eprintln!("unknown command: {command}");
            usage();
        }
    }

    Ok(())
}
