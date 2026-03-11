use std::ptr::addr_of;

use eidos_types::{BinaryKind, EidosError, Section, Symbol, Witness};

const MAX_TRACE_EVENTS: u32 = 1 << 20;

#[repr(C)]
pub struct CSection {
    pub name: [u8; 32],
    pub vaddr: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
    pub executable: u8,
    pub writable: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct CSym {
    pub name: [u8; 64],
    pub vaddr: u64,
    pub size: u64,
    pub is_func: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
pub struct CBinary {
    pub kind: u32,
    pub machine: u16,
    pub subtype: u16,
    pub entry: u64,
    pub base: u64,
    pub sections: *mut CSection,
    pub nsections: u32,
    pub symbols: *mut CSym,
    pub nsymbols: u32,
}

#[repr(C)]
pub struct CWitness {
    pub ip: u64,
    pub is_syscall_entry: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
pub struct CTrace {
    pub events: *mut CWitness,
    pub count: u32,
    pub cap: u32,
}

type ParseFn = unsafe extern "C" fn(*const u8, usize, *mut CBinary) -> i32;

extern "C" {
    pub fn eidos_elf_parse(data: *const u8, len: usize, out: *mut CBinary) -> i32;
    pub fn eidos_pe_parse(data: *const u8, len: usize, out: *mut CBinary) -> i32;
    pub fn eidos_macho_parse(data: *const u8, len: usize, out: *mut CBinary) -> i32;
    pub fn eidos_binary_free(b: *mut CBinary);

    pub fn eidos_trace_pid(pid: i32, max_events: u32, out: *mut CTrace) -> i32;
    pub fn eidos_trace_exec(
        argv: *const *mut libc::c_char,
        max_events: u32,
        out: *mut CTrace,
    ) -> i32;
    pub fn eidos_trace_free(t: *mut CTrace);
}

fn str_of(cstr: &[u8]) -> String {
    let end = cstr.iter().position(|&b| b == 0).unwrap_or(cstr.len());
    String::from_utf8_lossy(&cstr[..end]).into_owned()
}

pub struct ParsedBinary {
    pub kind: BinaryKind,
    pub machine: u16,
    pub subtype: u16,
    pub entry: u64,
    pub base: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

fn invoke(data: &[u8], parser: ParseFn) -> Result<ParsedBinary, EidosError> {
    let mut raw = std::mem::MaybeUninit::<CBinary>::uninit();
    let rc = unsafe { parser(data.as_ptr(), data.len(), raw.as_mut_ptr()) };
    if rc != 0 {
        return Err(EidosError::Native(rc));
    }
    let raw = unsafe { raw.assume_init() };

    let sections = if raw.sections.is_null() || raw.nsections == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(raw.sections, raw.nsections as usize) }
            .iter()
            .map(|s| {
                let start = s.offset as usize;
                let end = start.saturating_add(s.size as usize).min(data.len());
                Section {
                    name: str_of(&s.name),
                    vaddr: s.vaddr,
                    offset: s.offset,
                    size: s.size,
                    executable: s.executable != 0,
                    writable: s.writable != 0,
                    flags: s.flags,
                    entropy: crate::entropy::shannon(&data[start..end]),
                }
            })
            .collect()
    };

    let symbols = if raw.symbols.is_null() || raw.nsymbols == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(raw.symbols, raw.nsymbols as usize) }
            .iter()
            .map(|s| Symbol {
                name: str_of(&s.name),
                vaddr: s.vaddr,
                size: s.size,
                is_func: s.is_func != 0,
            })
            .collect()
    };

    let kind = BinaryKind::try_from(raw.kind).map_err(|_| EidosError::UnknownFormat)?;

    let result = ParsedBinary {
        kind,
        machine: raw.machine,
        subtype: raw.subtype,
        entry: raw.entry,
        base: raw.base,
        sections,
        symbols,
    };
    unsafe { eidos_binary_free(addr_of!(raw) as *mut CBinary) };
    Ok(result)
}

pub fn parse_elf(data: &[u8]) -> Result<ParsedBinary, EidosError> {
    invoke(data, eidos_elf_parse)
}

pub fn parse_pe(data: &[u8]) -> Result<ParsedBinary, EidosError> {
    invoke(data, eidos_pe_parse)
}

pub fn parse_macho(data: &[u8]) -> Result<ParsedBinary, EidosError> {
    invoke(data, eidos_macho_parse)
}

fn run_trace(rc: i32, raw: std::mem::MaybeUninit<CTrace>) -> Result<Vec<Witness>, EidosError> {
    if rc != 0 {
        return Err(EidosError::Native(rc));
    }
    let raw = unsafe { raw.assume_init() };
    let witnesses = sift(&raw);
    unsafe { eidos_trace_free(addr_of!(raw) as *mut CTrace) };
    Ok(witnesses)
}

pub fn trace_pid(pid: u32) -> Result<Vec<Witness>, EidosError> {
    let mut raw = std::mem::MaybeUninit::<CTrace>::uninit();
    let rc = unsafe { eidos_trace_pid(pid as i32, MAX_TRACE_EVENTS, raw.as_mut_ptr()) };
    run_trace(rc, raw)
}

pub fn trace_exec(path: &std::path::Path) -> Result<Vec<Witness>, EidosError> {
    let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| EidosError::Trace("nul in path".into()))?;
    let argv: Vec<*mut libc::c_char> = vec![cpath.as_ptr() as *mut _, std::ptr::null_mut()];

    let mut raw = std::mem::MaybeUninit::<CTrace>::uninit();
    let rc = unsafe {
        eidos_trace_exec(
            argv.as_ptr() as *const _,
            MAX_TRACE_EVENTS,
            raw.as_mut_ptr(),
        )
    };
    run_trace(rc, raw)
}

fn sift(raw: &CTrace) -> Vec<Witness> {
    if raw.events.is_null() || raw.count == 0 {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    unsafe { std::slice::from_raw_parts(raw.events, raw.count as usize) }
        .iter()
        .filter_map(|w| {
            seen.insert(w.ip).then_some(Witness {
                ip: w.ip,
                is_syscall: w.is_syscall_entry != 0,
            })
        })
        .collect()
}
