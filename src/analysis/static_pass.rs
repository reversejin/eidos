use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use capstone::arch::x86::X86Insn;
use capstone::prelude::*;
use memmap2::Mmap;

use eidos_types::{BinaryKind, Block, EidosError, Section, Symbol};

use crate::ffi::bindings::{parse_elf, parse_macho, parse_pe, ParsedBinary};

// TODO: replace with full CFG reconstruction once snapshotting is stable
pub struct Snap {
    pub kind: BinaryKind,
    pub machine: u16,
    pub entry: u64,
    pub base: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub blocks: Vec<Block>,
    pub raw: Vec<u8>,
}

pub fn snap(path: &Path) -> Result<Snap, EidosError> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let data = &mmap;

    let parsed = sense(data)?;
    let kind = parsed.kind;
    let blocks = carve(data, &parsed.sections, parsed.machine)?;
    let raw = data.to_vec();

    Ok(Snap {
        kind,
        machine: parsed.machine,
        entry: parsed.entry,
        base: parsed.base,
        sections: parsed.sections,
        symbols: parsed.symbols,
        blocks,
        raw,
    })
}

fn sense(data: &[u8]) -> Result<ParsedBinary, EidosError> {
    if data.len() < 4 {
        return Err(EidosError::Truncated);
    }
    match &data[..4] {
        [0x7f, b'E', b'L', b'F'] => parse_elf(data),
        [b'M', b'Z', ..] => parse_pe(data),
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe] => parse_macho(data),
        _ => Err(EidosError::UnknownFormat),
    }
}

fn carve(data: &[u8], sections: &[Section], machine: u16) -> Result<Vec<Block>, EidosError> {
    let cs = arm_cs(machine)?;
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let mut raw_insns: Vec<(u64, Vec<u64>)> = Vec::new();

    for sec in sections.iter().filter(|s| s.executable) {
        let start = sec.offset as usize;
        let end = start.saturating_add(sec.size as usize).min(data.len());
        if start >= end {
            continue;
        }
        let insns = cs
            .disasm_all(&data[start..end], sec.vaddr)
            .map_err(|e| EidosError::Capstone(e.to_string()))?;

        leaders.insert(sec.vaddr);

        for insn in insns.as_ref() {
            let addr = insn.address();
            let next = addr + insn.bytes().len() as u64;
            let succs = exits(&cs, insn, next);
            if !succs.is_empty() {
                for &t in &succs {
                    leaders.insert(t);
                }
                leaders.insert(next);
                raw_insns.push((addr, succs));
            }
        }
    }

    let leaders_vec = leaders.into_iter().collect::<Vec<_>>();
    let mut blocks: BTreeMap<u64, Block> = BTreeMap::new();

    for w in leaders_vec.windows(2) {
        blocks.insert(
            w[0],
            Block {
                start: w[0],
                end: w[1],
                successors: Vec::new(),
                witnessed: false,
            },
        );
    }
    if let Some(&last) = leaders_vec.last() {
        blocks.entry(last).or_insert(Block {
            start: last,
            end: last + 1,
            successors: Vec::new(),
            witnessed: false,
        });
    }

    for (addr, succs) in raw_insns {
        let mut deduped = succs;
        deduped.sort_unstable();
        deduped.dedup();

        let key = enclosing(&blocks, addr);
        if let Some(k) = key {
            if let Some(b) = blocks.get_mut(&k) {
                b.successors = deduped;
            }
        }
    }

    Ok(blocks.into_values().collect())
}

fn enclosing(blocks: &BTreeMap<u64, Block>, addr: u64) -> Option<u64> {
    blocks.range(..=addr).next_back().map(|(&k, _)| k)
}

fn arm_cs(machine: u16) -> Result<Capstone, EidosError> {
    match machine {
        0x8664 | 62 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .map_err(|e| EidosError::Capstone(e.to_string())),
        0x014c | 3 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build()
            .map_err(|e| EidosError::Capstone(e.to_string())),
        0xaa64 | 183 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|e| EidosError::Capstone(e.to_string())),
        m => Err(EidosError::UnsupportedArch(m)),
    }
}

fn exits(cs: &Capstone, insn: &capstone::Insn, fallthrough: u64) -> Vec<u64> {
    let detail = match cs.insn_detail(insn) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let arch = match detail.arch_detail() {
        capstone::arch::ArchDetail::X86Detail(d) => d,
        _ => return Vec::new(),
    };

    let id = insn.id().0;

    let is_jmp = id == X86Insn::X86_INS_JMP as u32;
    let is_jcc = is_conditional_jump(id);
    let is_call = id == X86Insn::X86_INS_CALL as u32;
    let is_ret = id == X86Insn::X86_INS_RET as u32
        || id == X86Insn::X86_INS_RETF as u32
        || id == X86Insn::X86_INS_RETFQ as u32;

    if is_ret {
        return Vec::new();
    }

    let imm: Option<u64> = arch.operands().find_map(|op| {
        if let capstone::arch::x86::X86OperandType::Imm(v) = op.op_type {
            Some(v as u64)
        } else {
            None
        }
    });

    if is_jmp {
        return imm.map(|t| vec![t]).unwrap_or_default();
    }
    if is_call {
        return vec![fallthrough];
    }
    if is_jcc {
        let mut out = vec![fallthrough];
        if let Some(t) = imm {
            out.push(t);
        }
        return out;
    }

    Vec::new()
}

fn is_conditional_jump(id: u32) -> bool {
    use X86Insn::*;
    // JAE(254)..JS(272) are contiguous in capstone
    let jcc = (X86_INS_JAE as u32)..=(X86_INS_JS as u32);
    // LOOP(348)..LOOPNE(350) are contiguous
    let loops = (X86_INS_LOOP as u32)..=(X86_INS_LOOPNE as u32);
    jcc.contains(&id) || loops.contains(&id)
}
