use suricata_ffi::{
    flow::{self, Flow, Packet, ThreadVars},
    SCLogNotice,
};

use crate::thread::{ExampleThreadStorage, THREAD_STORAGE_ID};

pub(crate) fn register() -> Result<(), &'static str> {
    flow::register_init_callback(|tv: *mut ThreadVars, f: *mut Flow, p: *const Packet| {
        SCLogNotice!(
            "Flow init callback (tv={:p}, flow={:p}, packet={:p})",
            tv,
            f,
            p
        );
    })?;

    flow::register_update_callback(|tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet| {
        SCLogNotice!(
            "Flow update callback (tv={:p}, flow={:p}, packet={:p})",
            tv,
            f,
            p,
        );

        if let Some(storage) = get_thread_storage(tv) {
            storage.count += 1;
        }
    })?;

    flow::register_finish_callback(|tv: *mut ThreadVars, f: *mut Flow| {
        SCLogNotice!("Flow finish callback (tv={:p}, flow={:p})", tv, f);
    })?;

    Ok(())
}

fn get_thread_storage(tv: *mut ThreadVars) -> Option<&'static mut ExampleThreadStorage> {
    let id = THREAD_STORAGE_ID.get().copied()?;
    unsafe { suricata_ffi::thread::storage::get_by_id(tv, id) }
}
