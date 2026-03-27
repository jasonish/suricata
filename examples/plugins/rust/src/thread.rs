use std::sync::OnceLock;

use suricata_ffi::{thread, SCLogError, SCLogNotice};
use suricata_sys::sys::{ThreadStorageId, ThreadVars};

#[derive(Debug, Default)]
pub(crate) struct ExampleThreadStorage {
    pub(crate) count: usize,
}

pub(crate) static THREAD_STORAGE_ID: OnceLock<ThreadStorageId> = OnceLock::new();

pub(crate) fn register() -> Result<(), &'static str> {
    let storage_id = suricata_ffi::thread::storage::register::<ExampleThreadStorage>("foo")?;
    THREAD_STORAGE_ID
        .set(storage_id)
        .map_err(|_| "Thread storage already registered")?;

    thread::callbacks::register_init_callback(|tv: *mut ThreadVars| {
        SCLogNotice!("Thread initialization callback (tv={:p})", tv);

        let Some(storage_id) = THREAD_STORAGE_ID.get().copied() else {
            SCLogError!("Thread storage id not available");
            return;
        };

        let storage = ExampleThreadStorage::default();
        if let Err(err) = unsafe { suricata_ffi::thread::storage::set_by_id(tv, storage_id, storage) } {
            SCLogError!("Failed to set thread storage: {}", err);
        }
    })?;

    Ok(())
}
