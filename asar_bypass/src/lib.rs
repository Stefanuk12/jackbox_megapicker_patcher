use std::path::Path;

use capstone::prelude::*;
use capstone::arch;
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use lightningscanner::{Scanner, pattern::Pattern};
use log::info;

pub mod error;
pub use error::*;

use crate::xrefs::XrefIterator;

mod xrefs;

/// Find the string in the image and return a file offset inside `data`.
fn locate_string(data: &[u8]) -> Result<usize> {
    let pattern = Pattern::new_string("Unsupported hashing algorithm in ValidateIntegrityOrDie");
    let scanner = Scanner::from(pattern);
    let result = unsafe { scanner.find(None, data.as_ptr(), data.len()) };
    Ok(result.get_addr() as usize - data.as_ptr() as usize)
}

/// Return the first xref VA to the string located at `file_off`.
fn find_first_xref_va(data: &[u8], file_off: usize) -> Result<Option<u64>> {
    let mut iter = XrefIterator::new(data, file_off)?;
    match iter.next() {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Given a parsed `PE` and a reference VA inside a section, find a likely
/// function start/end (file offsets) containing the reference. Uses a small
/// backwards scan for a common prologue and falls back to disassembly to
/// locate a return.
fn find_function_bounds(pe: &PE, ref_va: u64, data: &[u8]) -> Result<(usize, usize)> {
    let image_base = pe.image_base;

    // find containing section
    let mut sect_opt: Option<&SectionTable> = None;
    for sect in &pe.sections {
        let sec_va_start = image_base + sect.virtual_address as u64;
        let sec_va_end = sec_va_start + sect.virtual_size as u64;
        if ref_va >= sec_va_start && ref_va < sec_va_end {
            sect_opt = Some(sect);
            break;
        }
    }
    let sect = sect_opt.ok_or_else(|| Error::SectionNotFound)?;
    let section_va_base = image_base + sect.virtual_address as u64;
    let ref_file_off = sect.pointer_to_raw_data as usize
        + (ref_va.saturating_sub(section_va_base) as usize);

    // Prepare a Capstone handle for disassembly
    let cs = Capstone::new()
        .x86()
        .mode(if pe.is_64 {
            arch::x86::ArchMode::Mode64
        } else {
            arch::x86::ArchMode::Mode32
        })
        .detail(false)
        .build()?;

    // --- Find start: look backwards for a run of PUSH instructions followed by a stack alloc ---
    let search_back = 4096usize.min(ref_file_off);
    let search_file_start = ref_file_off.saturating_sub(search_back).max(sect.pointer_to_raw_data as usize);
    let search_file_end = ref_file_off.min(sect.pointer_to_raw_data as usize + sect.size_of_raw_data as usize).min(data.len());
    let mut func_start: Option<usize> = None;
    if search_file_start < search_file_end {
        let code = &data[search_file_start..search_file_end];
        let vabase = section_va_base + (search_file_start - sect.pointer_to_raw_data as usize) as u64;
        if let Ok(insns) = cs.disasm_all(code, vabase) {
            let insns_vec: Vec<_> = insns.iter().collect();
            // find the last instruction before the reference
            if let Some((last_idx, _)) = insns_vec.iter().enumerate().rev().find(|(_, i)| i.address() < ref_va) {
                // walk backward while we see PUSH instructions
                let mut start_idx = last_idx;
                while start_idx > 0 {
                    let prev = insns_vec[start_idx - 1];
                    if let Some(mn) = prev.mnemonic() {
                        if mn.starts_with("push") {
                            start_idx -= 1;
                            continue;
                        }
                    }
                    break;
                }
                // verify that at least one push was found at start_idx..=last_idx
                if start_idx <= last_idx {
                    // require that the instruction at start_idx is a push
                    if let Some(mn) = insns_vec[start_idx].mnemonic() {
                        if mn.starts_with("push") {
                            let start_va = insns_vec[start_idx].address();
                            func_start = Some((start_va - section_va_base) as usize + sect.pointer_to_raw_data as usize);
                        }
                    }
                }
            }
        }
    }

    // fallback: if not found, try to locate `sub rsp, imm` or `push rbp; mov rbp, rsp` near reference
    if func_start.is_none() {
        // small window before ref
        let small_start = ref_file_off.saturating_sub(1024).max(sect.pointer_to_raw_data as usize);
        let small_end = ref_file_off.min(sect.pointer_to_raw_data as usize + sect.size_of_raw_data as usize).min(data.len());
        if small_start < small_end {
            let code = &data[small_start..small_end];
            let vabase = section_va_base + (small_start - sect.pointer_to_raw_data as usize) as u64;
            if let Ok(insns) = cs.disasm_all(code, vabase) {
                let insns_vec: Vec<_> = insns.iter().collect();
                for (idx, insn) in insns_vec.iter().enumerate() {
                    if insn.address() >= ref_va { break; }
                    if let (Some(mn), Some(op)) = (insn.mnemonic(), insn.op_str()) {
                        if mn == "sub" && op.contains("rsp") {
                            // choose first push before it if present
                            let mut sidx = idx;
                            while sidx > 0 {
                                let prev = insns_vec[sidx - 1];
                                if let Some(pm) = prev.mnemonic() {
                                    if pm.starts_with("push") { sidx -= 1; continue; }
                                }
                                break;
                            }
                            let start_va = insns_vec[sidx].address();
                            func_start = Some((start_va - section_va_base) as usize + sect.pointer_to_raw_data as usize);
                            break;
                        }
                    }
                    if let Some(mn) = insn.mnemonic() {
                        if mn == "push" {
                            if idx + 1 < insns_vec.len() {
                                let next = insns_vec[idx + 1];
                                if let (Some(nmn), Some(nop)) = (next.mnemonic(), next.op_str()) {
                                    if nmn == "mov" && nop.contains("rbp") && nop.contains("rsp") {
                                        let start_va = insn.address();
                                        func_start = Some((start_va - section_va_base) as usize + sect.pointer_to_raw_data as usize);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // if still not found, default to bounded window below ref
    let func_start = func_start.unwrap_or_else(|| {
        let lower = ref_file_off.saturating_sub(0x2000);
        let sect_start = sect.pointer_to_raw_data as usize;
        if lower < sect_start { sect_start } else { lower }
    });

    // --- Find end: look forward for a run of POP instructions followed by RET ---
    let sect_file_start = sect.pointer_to_raw_data as usize;
    let sect_file_end = sect_file_start.saturating_add(sect.size_of_raw_data as usize).min(data.len());
    let mut func_end: Option<usize> = None;
    if ref_file_off < sect_file_end {
        let code = &data[ref_file_off..sect_file_end];
        let vabase = section_va_base + (ref_file_off - sect.pointer_to_raw_data as usize) as u64;
        if let Ok(insns) = cs.disasm_all(code, vabase) {
            let insns_vec: Vec<_> = insns.iter().collect();
            for (idx, insn) in insns_vec.iter().enumerate() {
                // detect sequence: one or more POP ... ; RET
                if let Some(mn) = insn.mnemonic() {
                    if mn.starts_with("pop") {
                        // check ahead for contiguous pops
                        let mut end_idx = idx;
                        while end_idx + 1 < insns_vec.len() {
                            let nxt = insns_vec[end_idx + 1];
                            if let Some(nmn) = nxt.mnemonic() {
                                if nmn.starts_with("pop") { end_idx += 1; continue; }
                            }
                            break;
                        }
                        // next instruction after pops should be ret
                        if end_idx + 1 < insns_vec.len() {
                            let candidate = insns_vec[end_idx + 1];
                            if let Some(cmn) = candidate.mnemonic() {
                                if cmn == "ret" {
                                    let end_va = candidate.address();
                                    func_end = Some((end_va - section_va_base) as usize + sect.pointer_to_raw_data as usize + candidate.bytes().len());
                                    break;
                                }
                            }
                        }
                    }
                    // also accept direct `ret` as end
                    if mn == "ret" {
                        let end_va = insn.address();
                        func_end = Some((end_va - section_va_base) as usize + sect.pointer_to_raw_data as usize + insn.bytes().len());
                        break;
                    }
                }
            }
        }
    }

    // fallback: try to find RET by disassembling from func_start
    if func_end.is_none() {
        let code = &data[func_start..sect_file_end];
        let vabase = section_va_base + (func_start - sect.pointer_to_raw_data as usize) as u64;
        if let Ok(insns) = cs.disasm_all(code, vabase) {
            for insn in insns.iter() {
                if let Some(mn) = insn.mnemonic() {
                    if mn == "ret" {
                        let end_va = insn.address();
                        func_end = Some((end_va - section_va_base) as usize + sect.pointer_to_raw_data as usize + insn.bytes().len());
                        break;
                    }
                }
            }
        }
    }

    // final fallback: bounded window after reference
    let func_end = func_end.unwrap_or_else(|| (ref_file_off.saturating_add(0x2000)).min(sect_file_end));

    // safety shrink if absurdly large
    let max_allowed = 0x20000usize; // 128 KiB
    if func_end.saturating_sub(func_start) > max_allowed {
        let new_start = ref_file_off.saturating_sub(0x2000).max(sect.pointer_to_raw_data as usize);
        let new_end = (ref_file_off.saturating_add(0x2000)).min(sect_file_end);
        info!("Function range too large (0x{:x}); shrinking to 0x{:x}-0x{:x}", func_start, new_start, new_end);
        return Ok((new_start, new_end));
    }

    Ok((func_start, func_end))
}

/// Apply the `xor eax,eax; ret` stub and NOP remaining bytes in the target
/// function range.
fn apply_stub_patch(data: &mut [u8], func_start: usize, func_end: usize) -> Result<()> {
    // Instruction bytes: 0x31 0xC0 0xC3
    let stub: [u8; 3] = [0x31, 0xC0, 0xC3];
    if func_start >= data.len() {
        return Err(Error::InvalidFunctionStart)?;
    }
    let func_len = func_end.saturating_sub(func_start);
    if func_len == 0 {
        return Err(Error::EmptyFunction)?;
    }

    // Write stub, truncated if function is smaller than stub size
    for (i, &b) in stub.iter().enumerate() {
        if i >= func_len {
            break;
        }
        data[func_start + i] = b;
    }

    // NOP the remaining bytes in the function (if any)
    if func_len > stub.len() {
        for b in &mut data[func_start + stub.len()..func_end] {
            *b = 0x90; // NOP
        }
    }

    Ok(())
}

/// Given an `.exe` for an Electron app with ASAR integrity enabled,
/// this function will NOP out the function responsible for validating the integrity: `ValidateIntegrityOrDie`
pub fn patch(data: &mut [u8]) -> Result<()> {
    let file_off = locate_string(data)?;
    let ref_va = find_first_xref_va(data, file_off)?.ok_or(Error::XrefNotFound)?;

    let pe = PE::parse(data)?;
    let (func_start, func_end) = find_function_bounds(&pe, ref_va, data)?;

    apply_stub_patch(data, func_start, func_end)?;

    info!(
        "Patched ValidateIntegrityOrDie at file 0x{:x}-0x{:x}",
        func_start, func_end
    );

    Ok(())
}

pub fn patch_file<P: AsRef<Path>>(input_path: P, output_path: Option<P>) -> Result<()> {
    let mut input_data = std::fs::read(&input_path)?;
    patch(&mut input_data)?;
    std::fs::write(output_path.unwrap_or(input_path), input_data)?;
    Ok(())
}