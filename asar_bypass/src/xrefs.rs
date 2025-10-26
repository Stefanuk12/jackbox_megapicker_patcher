use capstone::{arch::{self, x86::X86OperandType, ArchDetail, BuildsCapstone, DetailsArchInsn}, Capstone};
use goblin::pe::{section_table::SectionTable, PE};

use crate::{Error, Result};

/// Lazily-discover xrefs to a target string VA by disassembling executable
/// sections on demand. Yields `Result<u64, Error>` where `Ok` contains the
/// instruction VA that references the string and `Err` is any error during
/// scanning.
pub struct XrefIterator<'a> {
    data: &'a [u8],
    cs: Capstone,
    sections: Vec<SectionTable>,
    image_base: u64,
    target_va: u64,
    is_64: bool,

    // scanning state
    section_idx: usize,
    section_file_start: usize,
    section_size: usize,
    section_va_base: u64,
    section_pos: usize,
    finished: bool,
}

impl<'a> XrefIterator<'a> {
    /// Create a new lazy iterator for `data` and the string located at
    /// `file_off` (a file offset inside `data`).
    pub fn new(data: &'a [u8], file_off: usize) -> Result<XrefIterator<'a>> {
        let pe = PE::parse(data)?;
        let image_base = pe.image_base;
        let sections = pe.sections.clone();

        // map file_off -> RVA -> VA
        let mut rva = None;
        for sect in &pe.sections {
            let ptr = sect.pointer_to_raw_data as usize;
            let size = sect.size_of_raw_data as usize;
            if file_off >= ptr && file_off < ptr + size {
                let va_rva = sect.virtual_address as u64 + (file_off as u64 - ptr as u64);
                rva = Some(va_rva as u32);
                break;
            }
        }
        let rva = match rva {
            Some(r) => r,
            None => {
                return Err(Error::RvaNotFound);
            }
        };
        let target_va = image_base + rva as u64;

        let is_64 = pe.is_64;
        let cs = Capstone::new()
            .x86()
            .mode(if is_64 {
                arch::x86::ArchMode::Mode64
            } else {
                arch::x86::ArchMode::Mode32
            })
            .detail(true)
            .build()?;

        let mut it = XrefIterator {
            data,
            cs,
            sections,
            image_base,
            target_va,
            is_64,
            section_idx: 0,
            section_file_start: 0,
            section_size: 0,
            section_va_base: 0,
            section_pos: 0,
            finished: false,
        };

        // advance to first executable section
        it.advance_to_next_exec_section();
        Ok(it)
    }

    fn advance_to_next_exec_section(&mut self) {
        while self.section_idx < self.sections.len() {
            let sect = &self.sections[self.section_idx];
            self.section_idx += 1;
            if sect.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let start = sect.pointer_to_raw_data as usize;
            let size = sect.size_of_raw_data as usize;
            if start + size > self.data.len() {
                continue;
            }
            self.section_file_start = start;
            self.section_size = size;
            self.section_va_base = self.image_base + sect.virtual_address as u64;
            self.section_pos = 0;
            return;
        }
        self.finished = true;
    }
}

impl<'a> Iterator for XrefIterator<'a> {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            // If we've exhausted current section, advance
            if self.section_pos >= self.section_size {
                self.advance_to_next_exec_section();
                if self.finished {
                    return None;
                }
            }

            let file_off = self.section_file_start + self.section_pos;
            let code = &self.data[file_off..self.section_file_start + self.section_size];
            if code.is_empty() {
                self.advance_to_next_exec_section();
                if self.finished {
                    return None;
                }
                continue;
            }

            let vabase = self.section_va_base + self.section_pos as u64;
            let insns = match self
                .cs
                .disasm_count(code, vabase, 1)
                .map_err(Error::Capstone)
                .inspect_err(|_| self.finished = true)
            {
                Ok(x) => x,
                Err(err) => return Some(Err(err)),
            };

            if insns.len() == 0 {
                // nothing decodable at this position; advance by 1 to avoid infinite loop
                self.section_pos = self.section_pos.saturating_add(1);
                continue;
            }

            let insn = insns.iter().next().unwrap();
            let insn_len = insn.bytes().len();
            // default advance
            self.section_pos = self.section_pos.saturating_add(insn_len);

            // inspect operands for references
            let Ok(detail) = self.cs.insn_detail(&insn) else {
                continue;
            };

            let arch_detail = detail.arch_detail();
            let ArchDetail::X86Detail(x86_detail) = arch_detail else {
                continue;
            };

            for op in x86_detail.operands() {
                match op.op_type {
                    X86OperandType::Mem(mem) => {
                        let base = mem.base().0;
                        let disp = mem.disp();
                        let is_rip =
                            base == capstone::RegId(capstone_sys::x86_reg::X86_REG_RIP as u16).0;
                        if is_rip {
                            let target =
                                (insn.address() as i128 + insn_len as i128 + disp as i128) as u64;
                            if target == self.target_va {
                                return Some(Ok(insn.address()));
                            }
                        }
                    }
                    X86OperandType::Imm(imm) => {
                        if self.is_64 {
                            if imm as u64 == self.target_va {
                                return Some(Ok(insn.address()));
                            }
                        } else {
                            if (imm as u32) as u64 == self.target_va {
                                return Some(Ok(insn.address()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}