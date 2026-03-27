use suricata_ffi::{thread, SCLogNotice};
use suricata_sys::sys::ThreadVars;

pub(crate) fn register() -> Result<(), &'static str> {
    thread::register_init_callback(|tv: *mut ThreadVars| {
        SCLogNotice!("Thread initialization callback (tv={:p})", tv);
    })?;

    Ok(())
}
