#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use iced_x86::{CC_e, CC_ne, Decoder, DecoderOptions, Formatter, FormatterOutput,
    FormatterTextKind, Instruction, MasmFormatter, SymbolResolver, SymbolResult};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::BufRead;

// --- Raw record splitting ---

struct RawRecord {
    offset: usize,
    record_type: u8,
    payload: Vec<u8>,
}

fn split_records(data: &[u8]) -> Result<Vec<RawRecord>> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 3 > data.len() {
            bail!("truncated record header at offset 0x{:04x}", pos);
        }
        let record_type = data[pos];
        let length = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        if pos + 3 + length > data.len() {
            bail!(
                "truncated record payload at offset 0x{:04x}: need {} bytes, have {}",
                pos,
                length,
                data.len() - pos - 3
            );
        }
        let payload = if length > 0 {
            data[pos + 3..pos + 3 + length - 1].to_vec()
        } else {
            Vec::new()
        };
        records.push(RawRecord {
            offset: pos,
            record_type,
            payload,
        });
        pos += 3 + length;
    }
    Ok(records)
}

// --- Parsed record types ---

struct PubSym {
    name: String,
    offset: u32,
}

struct FixupSub {
    is_seg_relative: bool,
    location_type: u8,
    data_offset: u16,
    frame_method: u8,
    frame_datum: usize,
    frame_via_thread: bool,
    target_method: u8,
    target_datum: usize,
    target_via_thread: bool,
    displacement: u32,
}

struct ThreadSub {
    is_frame: bool,
    method: u8,
    thread_num: u8,
    index: usize,
}

struct LinnumEntry {
    line: u16,
    offset: u32,
}

enum Record {
    Theadr { name: String },
    Lheadr { name: String },
    Coment { attr: u8, class: u8, body: Vec<u8> },
    Lnames { names: Vec<String> },
    Segdef {
        is32: bool,
        acbp: u8,
        size: u32,
        name_idx: usize,
        class_idx: usize,
        overlay_idx: usize,
    },
    Grpdef {
        name_idx: usize,
        segs: Vec<usize>,
    },
    Pubdef {
        is32: bool,
        is_local: bool,
        grp_idx: usize,
        seg_idx: usize,
        base_frame: Option<u16>,
        symbols: Vec<PubSym>,
    },
    Extdef {
        is_local: bool,
        names: Vec<String>,
    },
    Ledata {
        is32: bool,
        seg_idx: usize,
        offset: u32,
        data: Vec<u8>,
    },
    Lidata {
        is32: bool,
        seg_idx: usize,
        offset: u32,
        data: Vec<u8>,
    },
    Fixupp {
        is32: bool,
        fixups: Vec<FixupSub>,
        threads: Vec<ThreadSub>,
    },
    Linnum {
        is32: bool,
        grp_idx: usize,
        seg_idx: usize,
        entries: Vec<LinnumEntry>,
    },
    Modend {
        is32: bool,
        has_start: bool,
    },
    Comdef {
        names: Vec<String>,
    },
    Unknown {
        record_type: u8,
        data: Vec<u8>,
    },
}

// --- Binary helpers ---

fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= data.len() {
        return None;
    }
    let len = data[*pos] as usize;
    *pos += 1;
    if *pos + len > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[*pos..*pos + len]).into_owned();
    *pos += len;
    Some(s)
}

fn read_u8(data: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= data.len() {
        return None;
    }
    let v = data[*pos];
    *pos += 1;
    Some(v)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > data.len() {
        return None;
    }
    let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Some(v)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > data.len() {
        return None;
    }
    let v = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Some(v)
}

fn read_index(data: &[u8], pos: &mut usize) -> Option<usize> {
    let b = read_u8(data, pos)?;
    if b & 0x80 != 0 {
        let b2 = read_u8(data, pos)?;
        Some((((b & 0x7f) as usize) << 8) | b2 as usize)
    } else {
        Some(b as usize)
    }
}

fn read_comlen(data: &[u8], pos: &mut usize) -> Option<u32> {
    let b = read_u8(data, pos)?;
    match b {
        0x81 => read_u16(data, pos).map(|v| v as u32),
        0x84 => {
            let lo = read_u16(data, pos)? as u32;
            let hi = read_u8(data, pos)? as u32;
            Some((hi << 16) | lo)
        }
        0x88 => read_u32(data, pos),
        _ => Some(b as u32),
    }
}

// --- Parsing ---

fn parse_record(raw: &RawRecord) -> Record {
    let d = &raw.payload;
    match raw.record_type {
        0x80 => {
            let mut p = 0;
            let name = read_str(d, &mut p).unwrap_or_default();
            Record::Theadr { name }
        }
        0x82 => {
            let mut p = 0;
            let name = read_str(d, &mut p).unwrap_or_default();
            Record::Lheadr { name }
        }
        0x88 => {
            let attr = d.first().copied().unwrap_or(0);
            let class = d.get(1).copied().unwrap_or(0);
            let body = if d.len() > 2 { d[2..].to_vec() } else { Vec::new() };
            Record::Coment { attr, class, body }
        }
        0x96 | 0xCC => {
            let mut p = 0;
            let mut names = Vec::new();
            while p < d.len() {
                match read_str(d, &mut p) {
                    Some(s) => names.push(s),
                    None => break,
                }
            }
            Record::Lnames { names }
        }
        0x98 | 0x99 => {
            let is32 = raw.record_type == 0x99;
            let mut p = 0;
            let acbp = read_u8(d, &mut p).unwrap_or(0);
            let a = (acbp >> 5) & 0x07;
            if a == 0 {
                p += 3; // skip frame(2) + offset(1) for absolute segments
            }
            let size = if is32 {
                read_u32(d, &mut p).unwrap_or(0)
            } else {
                read_u16(d, &mut p).unwrap_or(0) as u32
            };
            let name_idx = read_index(d, &mut p).unwrap_or(0);
            let class_idx = read_index(d, &mut p).unwrap_or(0);
            let overlay_idx = read_index(d, &mut p).unwrap_or(0);
            Record::Segdef { is32, acbp, size, name_idx, class_idx, overlay_idx }
        }
        0x9A => {
            let mut p = 0;
            let name_idx = read_index(d, &mut p).unwrap_or(0);
            let mut segs = Vec::new();
            while p < d.len() {
                let _desc_type = read_u8(d, &mut p);
                match read_index(d, &mut p) {
                    Some(idx) => segs.push(idx),
                    None => break,
                }
            }
            Record::Grpdef { name_idx, segs }
        }
        0x90 | 0x91 | 0xB6 | 0xB7 => {
            let is32 = raw.record_type == 0x91 || raw.record_type == 0xB7;
            let is_local = raw.record_type == 0xB6 || raw.record_type == 0xB7;
            let mut p = 0;
            let grp_idx = read_index(d, &mut p).unwrap_or(0);
            let seg_idx = read_index(d, &mut p).unwrap_or(0);
            let base_frame = if seg_idx == 0 {
                read_u16(d, &mut p)
            } else {
                None
            };
            let mut symbols = Vec::new();
            while p < d.len() {
                let name = match read_str(d, &mut p) {
                    Some(s) => s,
                    None => break,
                };
                let offset = if is32 {
                    read_u32(d, &mut p).unwrap_or(0)
                } else {
                    read_u16(d, &mut p).unwrap_or(0) as u32
                };
                let _type_idx = read_index(d, &mut p);
                symbols.push(PubSym { name, offset });
            }
            Record::Pubdef { is32, is_local, grp_idx, seg_idx, base_frame, symbols }
        }
        0x8C | 0xB4 => {
            let is_local = raw.record_type == 0xB4;
            let mut p = 0;
            let mut names = Vec::new();
            while p < d.len() {
                let name = match read_str(d, &mut p) {
                    Some(s) => s,
                    None => break,
                };
                let _type_idx = read_index(d, &mut p);
                names.push(name);
            }
            Record::Extdef { is_local, names }
        }
        0xA0 | 0xA1 => {
            let is32 = raw.record_type == 0xA1;
            let mut p = 0;
            let seg_idx = read_index(d, &mut p).unwrap_or(0);
            let offset = if is32 {
                read_u32(d, &mut p).unwrap_or(0)
            } else {
                read_u16(d, &mut p).unwrap_or(0) as u32
            };
            let data = d[p..].to_vec();
            Record::Ledata { is32, seg_idx, offset, data }
        }
        0xA2 | 0xA3 => {
            let is32 = raw.record_type == 0xA3;
            let mut p = 0;
            let seg_idx = read_index(d, &mut p).unwrap_or(0);
            let offset = if is32 {
                read_u32(d, &mut p).unwrap_or(0)
            } else {
                read_u16(d, &mut p).unwrap_or(0) as u32
            };
            let data = d[p..].to_vec();
            Record::Lidata { is32, seg_idx, offset, data }
        }
        0x9C | 0x9D => {
            let is32 = raw.record_type == 0x9D;
            let mut fixups = Vec::new();
            let mut threads = Vec::new();
            let mut p = 0;
            while p < d.len() {
                let b = d[p];
                if b & 0x80 != 0 {
                    // FIXUP subrecord: locat is 2 bytes
                    if p + 1 >= d.len() { break; }
                    let locat_hi = b;
                    let locat_lo = d[p + 1];
                    p += 2;
                    let is_seg_relative = (locat_hi & 0x40) != 0;
                    let location_type = (locat_hi >> 2) & 0x0f;
                    let data_offset = (((locat_hi & 0x03) as u16) << 8) | locat_lo as u16;

                    // fix_dat byte: F(7) FRAME(6-4) T(3) TARGT(2-0)
                    if p >= d.len() { break; }
                    let fix_dat = d[p];
                    p += 1;

                    let frame_via_thread = (fix_dat & 0x80) != 0;
                    let frame_method;
                    let mut frame_datum = 0usize;
                    if frame_via_thread {
                        frame_method = (fix_dat >> 4) & 0x03; // thread number
                    } else {
                        frame_method = (fix_dat >> 4) & 0x07;
                        if frame_method <= 2 {
                            frame_datum = read_index(d, &mut p).unwrap_or(0);
                        }
                    }

                    let target_via_thread = (fix_dat & 0x08) != 0;
                    let targt = fix_dat & 0x07;
                    let target_method;
                    let mut target_datum = 0usize;
                    let has_displacement;
                    if target_via_thread {
                        target_method = targt & 0x03; // thread number
                        has_displacement = (targt & 0x04) == 0;
                    } else {
                        target_method = targt & 0x03;
                        has_displacement = (targt & 0x04) == 0;
                        target_datum = read_index(d, &mut p).unwrap_or(0);
                    }

                    let displacement = if has_displacement {
                        if is32 {
                            read_u32(d, &mut p).unwrap_or(0)
                        } else {
                            read_u16(d, &mut p).unwrap_or(0) as u32
                        }
                    } else {
                        0
                    };

                    fixups.push(FixupSub {
                        is_seg_relative,
                        location_type,
                        data_offset,
                        frame_method,
                        frame_datum,
                        frame_via_thread,
                        target_method,
                        target_datum,
                        target_via_thread,
                        displacement,
                    });
                } else {
                    // THREAD subrecord
                    // bit 6: D (0=target, 1=frame)
                    // bit 5: 0 (reserved)
                    // bits 4-2: method
                    // bits 1-0: thread number
                    let is_frame = (b & 0x40) != 0;
                    let method = (b >> 2) & 0x07;
                    let thread_num = b & 0x03;
                    p += 1;
                    let index = if method <= 2 {
                        read_index(d, &mut p).unwrap_or(0)
                    } else {
                        0
                    };
                    threads.push(ThreadSub { is_frame, method, thread_num, index });
                }
            }
            Record::Fixupp { is32, fixups, threads }
        }
        0x94 | 0x95 => {
            let is32 = raw.record_type == 0x95;
            let mut p = 0;
            let grp_idx = read_index(d, &mut p).unwrap_or(0);
            let seg_idx = read_index(d, &mut p).unwrap_or(0);
            let mut entries = Vec::new();
            while p < d.len() {
                let line = match read_u16(d, &mut p) {
                    Some(v) => v,
                    None => break,
                };
                let offset = if is32 {
                    read_u32(d, &mut p).unwrap_or(0)
                } else {
                    read_u16(d, &mut p).unwrap_or(0) as u32
                };
                entries.push(LinnumEntry { line, offset });
            }
            Record::Linnum { is32, grp_idx, seg_idx, entries }
        }
        0x8A | 0x8B => {
            let is32 = raw.record_type == 0x8B;
            let has_start = !d.is_empty() && (d[0] & 0x40) != 0;
            Record::Modend { is32, has_start }
        }
        0xB0 => {
            let mut p = 0;
            let mut names = Vec::new();
            while p < d.len() {
                let name = match read_str(d, &mut p) {
                    Some(s) => s,
                    None => break,
                };
                let _type_idx = read_index(d, &mut p);
                let _data_type = read_u8(d, &mut p);
                let _ = read_comlen(d, &mut p);
                names.push(name);
            }
            Record::Comdef { names }
        }
        _ => {
            Record::Unknown { record_type: raw.record_type, data: d.clone() }
        }
    }
}

// --- Module (resolved state) ---

struct SegInfo {
    name_idx: usize,
    class_idx: usize,
    size: u32,
}

struct GrpInfo {
    name_idx: usize,
    segs: Vec<usize>,
}

struct OmfModule {
    lnames: Vec<String>,
    segments: Vec<SegInfo>,
    groups: Vec<GrpInfo>,
    extdefs: Vec<String>,
}

impl OmfModule {
    fn build(records: &[Record]) -> OmfModule {
        let mut m = OmfModule {
            lnames: Vec::new(),
            segments: Vec::new(),
            groups: Vec::new(),
            extdefs: Vec::new(),
        };
        for rec in records {
            match rec {
                Record::Lnames { names } => {
                    m.lnames.extend(names.iter().cloned());
                }
                Record::Segdef { name_idx, class_idx, size, .. } => {
                    m.segments.push(SegInfo {
                        name_idx: *name_idx,
                        class_idx: *class_idx,
                        size: *size,
                    });
                }
                Record::Grpdef { name_idx, segs } => {
                    m.groups.push(GrpInfo {
                        name_idx: *name_idx,
                        segs: segs.clone(),
                    });
                }
                Record::Extdef { names, .. } => {
                    m.extdefs.extend(names.iter().cloned());
                }
                _ => {}
            }
        }
        m
    }

    fn lname(&self, idx: usize) -> String {
        if idx == 0 {
            return "(none)".to_string();
        }
        match self.lnames.get(idx - 1) {
            Some(s) if s.is_empty() => format!("\"\" (#{idx})"),
            Some(s) => format!("\"{}\"", s),
            None => format!("#{idx}"),
        }
    }

    fn seg_label(&self, idx: usize) -> String {
        if idx == 0 {
            return "(abs)".to_string();
        }
        match self.segments.get(idx - 1) {
            Some(seg) => {
                let name = match self.lnames.get(seg.name_idx.wrapping_sub(1)) {
                    Some(s) if !s.is_empty() => s.as_str(),
                    _ => "?",
                };
                format!("#{idx} {name}")
            }
            None => format!("#{idx}"),
        }
    }

    fn seg_num(&self, rec_index: usize, records: &[Record]) -> usize {
        let mut count = 0;
        for (i, r) in records.iter().enumerate() {
            if matches!(r, Record::Segdef { .. }) {
                count += 1;
                if i == rec_index {
                    return count;
                }
            }
        }
        0
    }

    fn grp_num(&self, rec_index: usize, records: &[Record]) -> usize {
        let mut count = 0;
        for (i, r) in records.iter().enumerate() {
            if matches!(r, Record::Grpdef { .. }) {
                count += 1;
                if i == rec_index {
                    return count;
                }
            }
        }
        0
    }

    fn extdef_name(&self, idx: usize) -> String {
        if idx == 0 {
            return "(none)".to_string();
        }
        match self.extdefs.get(idx - 1) {
            Some(s) => s.clone(),
            None => format!("ext#{idx}"),
        }
    }

    fn grp_label(&self, idx: usize) -> String {
        if idx == 0 {
            return "(none)".to_string();
        }
        match self.groups.get(idx - 1) {
            Some(grp) => match self.lnames.get(grp.name_idx.wrapping_sub(1)) {
                Some(s) if !s.is_empty() => s.clone(),
                _ => format!("grp#{idx}"),
            },
            None => format!("grp#{idx}"),
        }
    }

    fn fixup_target_label(&self, method: u8, datum: usize) -> String {
        match method & 0x03 {
            0 => self.seg_label(datum),   // segment index
            1 => self.grp_label(datum),   // group index
            2 => self.extdef_name(datum), // external index
            _ => format!("?({method},{datum})"),
        }
    }

    /// Reconstruct a segment's data by merging all LEDATA records.
    fn segment_data(&self, seg_idx: usize, records: &[Record]) -> Vec<u8> {
        let size = self.segments.get(seg_idx - 1).map_or(0, |s| s.size) as usize;
        let mut buf = vec![0u8; size];
        for rec in records {
            if let Record::Ledata { seg_idx: si, offset, data, .. } = rec {
                if *si == seg_idx {
                    let start = *offset as usize;
                    let end = (start + data.len()).min(buf.len());
                    let copy_len = end.saturating_sub(start);
                    if copy_len > 0 {
                        buf[start..end].copy_from_slice(&data[..copy_len]);
                    }
                }
            }
        }
        buf
    }

    /// Compute base addresses for each segment using PUBDEF symbols + symbol table.
    fn segment_bases(&self, records: &[Record], symbols: &SymbolTable) -> HashMap<usize, u64> {
        let mut bases = HashMap::new();
        for rec in records {
            if let Record::Pubdef { seg_idx, symbols: syms, .. } = rec {
                if bases.contains_key(seg_idx) {
                    continue;
                }
                for sym in syms {
                    if let Some(addr) = symbols.lookup_name(&sym.name) {
                        bases.insert(*seg_idx, addr - sym.offset as u64);
                        break;
                    }
                }
            }
        }
        bases
    }

    /// Apply fixups to segment data using symbol table for address resolution.
    fn apply_fixups(
        &self,
        seg_idx: usize,
        buf: &mut [u8],
        records: &[Record],
        symbols: &SymbolTable,
        seg_bases: &HashMap<usize, u64>,
    ) {
        let seg_base = seg_bases.get(&seg_idx).copied().unwrap_or(0);

        // walk records: track last LEDATA, apply following FIXUPPs
        let mut last_ledata: Option<(usize, u32)> = None; // (seg_idx, offset)
        for rec in records {
            match rec {
                Record::Ledata { seg_idx: si, offset, .. } => {
                    last_ledata = Some((*si, *offset));
                }
                Record::Fixupp { fixups, threads, is32 } => {
                    let Some((le_seg, le_offset)) = last_ledata else { continue };
                    if le_seg != seg_idx { continue; }

                    // build thread tables for this FIXUPP record
                    let mut target_threads: [Option<(u8, usize)>; 4] = [None; 4];
                    for t in threads {
                        if !t.is_frame {
                            target_threads[t.thread_num as usize] = Some((t.method, t.index));
                        }
                    }

                    for f in fixups {
                        // resolve target method and datum
                        let (tgt_method, tgt_datum) = if f.target_via_thread {
                            match target_threads[f.target_method as usize] {
                                Some(v) => v,
                                None => continue,
                            }
                        } else {
                            (f.target_method, f.target_datum)
                        };

                        // resolve target to absolute address
                        let target_addr = match tgt_method & 0x03 {
                            0 => {
                                // segment + displacement
                                let tgt_base = seg_bases.get(&tgt_datum).copied().unwrap_or(0);
                                tgt_base + f.displacement as u64
                            }
                            1 => {
                                // group + displacement — use first segment in group
                                if let Some(grp) = self.groups.get(tgt_datum.wrapping_sub(1)) {
                                    let first_seg = grp.segs.first().copied().unwrap_or(0);
                                    let tgt_base = seg_bases.get(&first_seg).copied().unwrap_or(0);
                                    tgt_base + f.displacement as u64
                                } else {
                                    continue;
                                }
                            }
                            2 => {
                                // external — look up by name
                                let ext_name = match self.extdefs.get(tgt_datum.wrapping_sub(1)) {
                                    Some(n) => n.as_str(),
                                    None => continue,
                                };
                                match symbols.lookup_name(ext_name) {
                                    Some(addr) => addr + f.displacement as u64,
                                    None => continue,
                                }
                            }
                            _ => continue,
                        };

                        // compute patch location in segment buffer
                        let patch_offset = le_offset as usize + f.data_offset as usize;
                        let patch_size = match f.location_type {
                            1 | 5 => 2,      // offset16
                            9 | 13 => 4,     // offset32
                            _ => continue,    // skip unsupported types for now
                        };
                        if patch_offset + patch_size > buf.len() {
                            continue;
                        }

                        // compute patched value
                        let value = if f.is_seg_relative {
                            // direct/absolute: value is the target address
                            target_addr
                        } else {
                            // self-relative: value = target - (patch_location + patch_size)
                            let fixup_addr = seg_base + patch_offset as u64;
                            target_addr.wrapping_sub(fixup_addr + patch_size as u64)
                        };

                        // write
                        match patch_size {
                            2 => {
                                let bytes = (value as u16).to_le_bytes();
                                buf[patch_offset..patch_offset + 2].copy_from_slice(&bytes);
                            }
                            4 => {
                                let bytes = (value as u32).to_le_bytes();
                                buf[patch_offset..patch_offset + 4].copy_from_slice(&bytes);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {
                    // non-LEDATA/FIXUPP clears the LEDATA context
                    if !matches!(rec, Record::Fixupp { .. }) {
                        last_ledata = None;
                    }
                }
            }
        }
    }

    /// Find a public symbol by name. Returns (seg_idx, offset).
    fn find_pubsym(&self, name: &str, records: &[Record]) -> Option<(usize, u32)> {
        for rec in records {
            if let Record::Pubdef { seg_idx, symbols, .. } = rec {
                for sym in symbols {
                    if sym.name == name {
                        return Some((*seg_idx, sym.offset));
                    }
                }
            }
        }
        None
    }

    /// Collect all public symbols in a given segment, sorted by offset.
    fn segment_symbols(&self, seg_idx: usize, records: &[Record]) -> Vec<(String, u32)> {
        let mut syms = Vec::new();
        for rec in records {
            if let Record::Pubdef { seg_idx: si, symbols, .. } = rec {
                if *si == seg_idx {
                    for sym in symbols {
                        syms.push((sym.name.clone(), sym.offset));
                    }
                }
            }
        }
        syms.sort_by_key(|&(_, off)| off);
        syms
    }
}

// --- Dump formatting ---

fn record_type_name(ty: u8) -> &'static str {
    match ty {
        0x80 => "THEADR",
        0x82 => "LHEADR",
        0x88 => "COMENT",
        0x8A => "MODEND",
        0x8B => "MODEND32",
        0x8C => "EXTDEF",
        0x90 => "PUBDEF",
        0x91 => "PUBDEF32",
        0x94 => "LINNUM",
        0x95 => "LINNUM32",
        0x96 => "LNAMES",
        0x98 => "SEGDEF",
        0x99 => "SEGDEF32",
        0x9A => "GRPDEF",
        0x9C => "FIXUPP",
        0x9D => "FIXUPP32",
        0xA0 => "LEDATA",
        0xA1 => "LEDATA32",
        0xA2 => "LIDATA",
        0xA3 => "LIDATA32",
        0xB0 => "COMDEF",
        0xB4 => "LEXTDEF",
        0xB6 => "LPUBDEF",
        0xB7 => "LPUBDEF32",
        0xB8 => "LCOMDEF",
        0xC2 => "COMDAT",
        0xC3 => "COMDAT32",
        0xC6 => "ALIAS",
        0xCC => "LLNAMES",
        _ => "???",
    }
}

fn dump_record(raw: &RawRecord, rec: &Record, rec_index: usize, module: &OmfModule, records: &[Record]) {
    let type_name = record_type_name(raw.record_type);
    let len = raw.payload.len() + 1;
    print!("0x{:04x}  {:<12}len={:<6}", raw.offset, type_name, len);

    match rec {
        Record::Theadr { name } | Record::Lheadr { name } => {
            print!("{name}");
        }
        Record::Coment { class, body, .. } => {
            print!("class=0x{class:02x}");
            if !body.is_empty() {
                // try length-prefixed string
                let mut p = 0;
                let s = read_str(body, &mut p);
                if let Some(ref s) = s {
                    if p == body.len() && !s.is_empty() {
                        print!(" \"{s}\"");
                    } else if body.iter().all(|&b| b >= 0x20 && b < 0x7f) {
                        print!(" \"{}\"", String::from_utf8_lossy(body));
                    } else {
                        print!(" ({} bytes)", body.len());
                    }
                } else {
                    print!(" ({} bytes)", body.len());
                }
            }
        }
        Record::Lnames { names } => {
            let display: Vec<String> = names
                .iter()
                .map(|s| if s.is_empty() { "\"\"".to_string() } else { format!("\"{s}\"") })
                .collect();
            print!("{}", display.join(", "));
        }
        Record::Segdef { name_idx, class_idx, size, .. } => {
            let num = module.seg_num(rec_index, records);
            print!(
                "#{num} name={} class={} size=0x{size:04x}",
                module.lname(*name_idx),
                module.lname(*class_idx),
            );
        }
        Record::Grpdef { name_idx, segs } => {
            let num = module.grp_num(rec_index, records);
            let seg_names: Vec<String> = segs.iter().map(|&i| module.seg_label(i)).collect();
            print!("#{num} {} = {}", module.lname(*name_idx), seg_names.join(", "));
        }
        Record::Pubdef { is_local, seg_idx, symbols, .. } => {
            if *is_local { print!("(local) "); }
            print!("seg {}: ", module.seg_label(*seg_idx));
            let sym_strs: Vec<String> = symbols
                .iter()
                .map(|s| format!("{} @ 0x{:04x}", s.name, s.offset))
                .collect();
            print!("{}", sym_strs.join(", "));
        }
        Record::Extdef { is_local, names } => {
            if *is_local { print!("(local) "); }
            print!("{}", names.join(", "));
        }
        Record::Ledata { seg_idx, offset, data, .. } => {
            print!(
                "seg {} @ 0x{offset:04x} ({} bytes)",
                module.seg_label(*seg_idx),
                data.len(),
            );
        }
        Record::Lidata { seg_idx, offset, .. } => {
            print!("seg {} @ 0x{offset:04x}", module.seg_label(*seg_idx));
        }
        Record::Fixupp { fixups, threads, .. } => {
            let loc_type_name = |t: u8| -> &'static str {
                match t {
                    0 => "lobyte",
                    1 => "offset16",
                    2 => "base",
                    3 => "ptr16:16",
                    4 => "hibyte",
                    5 => "offset16(lr)",
                    9 => "offset32",
                    11 => "ptr16:32",
                    13 => "offset32(lr)",
                    _ => "?",
                }
            };
            // build thread table for resolving thread-based fixups
            let mut target_threads: [Option<(u8, usize)>; 4] = [None; 4];
            for t in threads {
                if !t.is_frame {
                    target_threads[t.thread_num as usize] = Some((t.method, t.index));
                }
            }
            for f in fixups {
                let rel = if f.is_seg_relative { "direct" } else { "self-rel" };
                let target = if f.target_via_thread {
                    match target_threads[f.target_method as usize] {
                        Some((method, datum)) => module.fixup_target_label(method, datum),
                        None => format!("thread#{}", f.target_method),
                    }
                } else {
                    module.fixup_target_label(f.target_method, f.target_datum)
                };
                print!(
                    "{rel} {typ} @0x{off:03x} -> {target}",
                    typ = loc_type_name(f.location_type),
                    off = f.data_offset,
                );
                if f.displacement != 0 {
                    print!("+0x{:x}", f.displacement);
                }
                print!("; ");
            }
        }
        Record::Linnum { seg_idx, entries, .. } => {
            print!("seg {}: {} line(s)", module.seg_label(*seg_idx), entries.len());
        }
        Record::Modend { has_start, .. } => {
            if *has_start { print!("(has start address)"); }
        }
        Record::Comdef { names } => {
            print!("{}", names.join(", "));
        }
        Record::Unknown { data, .. } => {
            if !data.is_empty() { print!("({} bytes)", data.len()); }
        }
    }
    println!();
}

// --- Commands ---

struct UppercaseOutput {
    s: String,
    uppercase_keywords: bool,
}

impl UppercaseOutput {
    fn new(uppercase_keywords: bool) -> Self {
        Self { s: String::new(), uppercase_keywords }
    }
}

impl FormatterOutput for UppercaseOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Register => {
                self.s.push_str(&text.to_uppercase());
            }
            FormatterTextKind::Keyword => {
                if self.uppercase_keywords {
                    self.s.push_str(&text.to_uppercase());
                } else {
                    self.s.push_str(text);
                }
            }
            _ => self.s.push_str(text),
        }
    }
}

#[derive(Deserialize)]
struct SymbolEntry {
    address: String,
    name: String,
}

struct SymbolTable {
    by_address: HashMap<u64, String>,
    by_name: HashMap<String, u64>,
}

impl SymbolTable {
    fn load(path: &str) -> Result<SymbolTable> {
        let file = fs::File::open(path).with_context(|| format!("failed to open {path}"))?;
        let reader = std::io::BufReader::new(file);
        let mut by_address = HashMap::new();
        let mut by_name = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() { continue; }
            let entry: SymbolEntry = serde_json::from_str(&line)
                .with_context(|| format!("failed to parse symbol entry"))?;
            let addr = u64::from_str_radix(&entry.address, 16)
                .with_context(|| format!("bad address: {}", entry.address))?;
            by_address.insert(addr, entry.name.clone());
            by_name.insert(entry.name, addr);
        }
        Ok(SymbolTable { by_address, by_name })
    }

    /// Look up an OBJ symbol name in the Ghidra symbol table.
    /// Tries: exact match, strip leading `_`, and DLL::Name suffix match.
    fn lookup_name(&self, obj_name: &str) -> Option<u64> {
        if let Some(&addr) = self.by_name.get(obj_name) {
            return Some(addr);
        }
        // Borland C prepends _ to __cdecl symbols
        if let Some(stripped) = obj_name.strip_prefix('_') {
            if let Some(&addr) = self.by_name.get(stripped) {
                return Some(addr);
            }
        }
        // Win32 imports: Ghidra uses "DLL::FuncName" format
        let suffix = format!("::{obj_name}");
        for (name, &addr) in &self.by_name {
            if name.ends_with(&suffix) {
                return Some(addr);
            }
        }
        None
    }
}

fn usage() -> ! {
    eprintln!("usage: obj-extract <command> [args...]");
    eprintln!("  dump <file>                                 dump all OMF records");
    eprintln!("  disasm [--with-symbols <symfile>] [--compact] <file> <symbol>  disassemble a function");
    std::process::exit(1);
}

fn load_module(path: &str) -> Result<(Vec<RawRecord>, Vec<Record>, OmfModule)> {
    let data = fs::read(path).with_context(|| format!("failed to read {path}"))?;
    let raws = split_records(&data).with_context(|| format!("failed to parse {path}"))?;
    let records: Vec<Record> = raws.iter().map(|r| parse_record(r)).collect();
    let module = OmfModule::build(&records);
    Ok((raws, records, module))
}

/// Pad absolute memory addresses like [0x490eec] to [0x00490eec] (8 hex digits).
/// Only pads addresses that appear as bare [0xNNN] (no register base).
fn pad_absolute_addrs(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find("[0x") {
        // Check this is a bare address: the char before 0x should be '['
        result.push_str(&rest[..idx + 1]); // include the '['
        rest = &rest[idx + 1..];
        // rest now starts with "0x..."
        // extract the hex digits after "0x"
        let hex_start = 2; // skip "0x"
        let hex_end = rest[hex_start..].find(|c: char| !c.is_ascii_hexdigit())
            .map(|i| i + hex_start)
            .unwrap_or(rest.len());
        let hex_digits = &rest[hex_start..hex_end];
        if hex_digits.len() < 8 {
            result.push_str("0x");
            for _ in 0..(8 - hex_digits.len()) {
                result.push('0');
            }
            result.push_str(hex_digits);
        } else {
            result.push_str(&rest[..hex_end]);
        }
        rest = &rest[hex_end..];
    }
    result.push_str(rest);
    result
}

fn cmd_disasm(path: &str, symbol_name: &str, sym_file: Option<&str>, compact: bool) -> Result<()> {
    let (_raws, records, module) = load_module(path)?;

    let (seg_idx, sym_offset) = module
        .find_pubsym(symbol_name, &records)
        .ok_or_else(|| anyhow::anyhow!("symbol not found: {symbol_name}"))?;

    let mut seg_data = module.segment_data(seg_idx, &records);
    let syms = module.segment_symbols(seg_idx, &records);

    // find function end: next symbol after this one, or end of segment data
    let func_end = syms
        .iter()
        .find(|&&(_, off)| off > sym_offset)
        .map(|&(_, off)| off)
        .unwrap_or(seg_data.len() as u32);

    // load symbol table and find base address
    let symbols = match sym_file {
        Some(f) => Some(SymbolTable::load(f)?),
        None => None,
    };
    let base_addr: u64 = match &symbols {
        Some(st) => {
            st.lookup_name(symbol_name)
                .ok_or_else(|| anyhow::anyhow!(
                    "{symbol_name} not found in symbol table"
                ))?
        }
        None => sym_offset as u64,
    };

    // apply fixups if we have a symbol table
    if let Some(ref st) = symbols {
        let seg_bases = module.segment_bases(&records, st);
        module.apply_fixups(seg_idx, &mut seg_data, &records, st, &seg_bases);
    }

    let start = sym_offset as usize;
    let end = func_end as usize;
    if start >= seg_data.len() {
        bail!("{symbol_name}: offset 0x{start:04x} is beyond segment data");
    }
    let code = &seg_data[start..end.min(seg_data.len())];

    if !compact {
        println!("{symbol_name}:");
    }
    let ip_start = base_addr;
    let mut decoder = Decoder::with_ip(32, code, ip_start, DecoderOptions::NONE);

    let resolver: Option<Box<dyn SymbolResolver>> = if compact {
        None
    } else {
        match &symbols {
            Some(st) => {
                // SymbolResolver needs 'static, so we build an owned lookup table
                let owned: HashMap<u64, String> = st.by_address.clone();
                Some(Box::new(OwnedSymbolResolver { symbols: owned }))
            }
            None => None,
        }
    };

    let mut formatter = MasmFormatter::with_options(resolver, None);
    formatter.options_mut().set_uppercase_mnemonics(true);
    formatter.options_mut().set_uppercase_registers(true);
    formatter.options_mut().set_space_after_operand_separator(false);
    if compact {
        // Ghidra-style: 0x prefix, lowercase hex digits, lowercase keywords,
        // spaces in memory operands, no branch size hints
        formatter.options_mut().set_uppercase_keywords(false);
        formatter.options_mut().set_uppercase_hex(false);
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_space_between_memory_add_operators(true);
        formatter.options_mut().set_space_between_memory_mul_operators(true);
        formatter.options_mut().set_show_branch_size(false);
        formatter.options_mut().set_branch_leading_zeros(true);
        formatter.options_mut().set_leading_zeros(false);
        formatter.options_mut().set_small_hex_numbers_in_decimal(false);
        formatter.options_mut().set_cc_e(CC_e::z);
        formatter.options_mut().set_cc_ne(CC_ne::nz);
    } else {
        formatter.options_mut().set_uppercase_keywords(true);
        formatter.options_mut().set_uppercase_all(true);
    }
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let ip = instr.ip();

        // format the mnemonic
        let mut upper_output = UppercaseOutput::new(!compact);
        formatter.format(&instr, &mut upper_output);
        let mnemonic = upper_output.s;

        if compact {
            // Ghidra-style: "addr: MNEMONIC operands"
            // Strip default segment prefixes (DS:, SS:) that Ghidra suppresses
            let mnemonic = mnemonic.replace("DS:", "").replace("SS:", "");
            // Pad bare absolute addresses [0xNNN] to 8 digits to match Ghidra
            let mnemonic = pad_absolute_addrs(&mnemonic);
            println!("{ip:08x}: {mnemonic} ");
        } else {
            let instr_len = instr.len();
            let instr_start = (ip - ip_start) as usize;
            let bytes = &code[instr_start..instr_start + instr_len];

            // split formatted text into opcode and operands for column alignment
            let (opcode, operands) = match mnemonic.find(' ') {
                Some(i) => (&mnemonic[..i], &mnemonic[i + 1..]),
                None => (mnemonic.as_str(), ""),
            };

            // <=4 bytes: all on first line; >4 bytes: 3 on first line
            let first_chunk = if bytes.len() > 4 { 3 } else { bytes.len() };
            let hex: String = bytes[..first_chunk]
                .iter()
                .map(|b| format!("{b:02x} "))
                .collect();
            println!("        {ip:08x} {hex:<16}{opcode:<11}{operands}");

            // continuation lines for long instructions
            let mut off = first_chunk;
            while off < bytes.len() {
                let chunk_end = (off + 4).min(bytes.len());
                let hex: String = bytes[off..chunk_end]
                    .iter()
                    .map(|b| format!("{b:02x} "))
                    .collect();
                println!("                 {hex}");
                off = chunk_end;
            }
        }
    }

    Ok(())
}

struct OwnedSymbolResolver {
    symbols: HashMap<u64, String>,
}

impl SymbolResolver for OwnedSymbolResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        let name = self.symbols.get(&address)?;
        Some(SymbolResult::with_str(address, name.as_str()))
    }
}

fn cmd_dump(path: &str) -> Result<()> {
    let (raws, records, module) = load_module(path)?;
    for (i, (raw, rec)) in raws.iter().zip(records.iter()).enumerate() {
        dump_record(raw, rec, i, &module, &records);
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    match args[1].as_str() {
        "dump" => {
            if args.len() < 3 {
                usage();
            }
            cmd_dump(&args[2])?;
        }
        "disasm" => {
            let mut i = 2;
            let mut sym_file = None;
            let mut compact = false;
            while i < args.len() && args[i].starts_with('-') {
                match args[i].as_str() {
                    "--with-symbols" => {
                        i += 1;
                        if i >= args.len() { usage(); }
                        sym_file = Some(args[i].as_str());
                        i += 1;
                    }
                    "--compact" => {
                        compact = true;
                        i += 1;
                    }
                    _ => usage(),
                }
            }
            if i + 2 > args.len() { usage(); }
            let obj_path = &args[i];
            let symbol_name = &args[i + 1];
            cmd_disasm(obj_path, symbol_name, sym_file, compact)?;
        }
        _ => usage(),
    }
    Ok(())
}
