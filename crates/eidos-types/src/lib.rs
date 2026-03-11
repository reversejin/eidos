use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EidosError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a recognised binary format")]
    UnknownFormat,
    #[error("binary too small or truncated")]
    Truncated,
    #[error("c layer: errno {}", .0.unsigned_abs())]
    Native(i32),
    #[error("disassembly engine: {0}")]
    Capstone(String),
    #[error("ptrace: {0}")]
    Trace(String),
    #[error("unsupported machine architecture: {0:#06x}")]
    UnsupportedArch(u16),
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    Elf,
    Pe,
    MachO,
}

impl TryFrom<u32> for BinaryKind {
    type Error = EidosError;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(BinaryKind::Elf),
            2 => Ok(BinaryKind::Pe),
            3 => Ok(BinaryKind::MachO),
            _ => Err(EidosError::UnknownFormat),
        }
    }
}

impl fmt::Display for BinaryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BinaryKind::Elf   => "ELF",
            BinaryKind::Pe    => "PE",
            BinaryKind::MachO => "Mach-O",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Static,
    Dynamic,
    Hybrid,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name:       String,
    pub vaddr:      u64,
    pub offset:     u64,
    pub size:       u64,
    pub executable: bool,
    pub writable:   bool,
    pub flags:      u32,
    pub entropy:    f64,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name:    String,
    pub vaddr:   u64,
    pub size:    u64,
    pub is_func: bool,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub start:      u64,
    pub end:        u64,
    pub successors: Vec<u64>,
    pub witnessed:  bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Witness {
    pub ip:         u64,
    pub is_syscall: bool,
}
