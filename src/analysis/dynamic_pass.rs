use std::path::Path;

use eidos_types::{EidosError, Witness};

use crate::ffi::bindings::{trace_exec, trace_pid};

pub fn trace(
    path: &Path,
    pid: Option<u32>,
) -> Result<Vec<Witness>, EidosError> {
    match pid {
        Some(0) => Err(EidosError::Trace(
            "pid 0 is not a valid target".into(),
        )),
        Some(p) => trace_pid(p),
        None => trace_exec(path),
    }
}
