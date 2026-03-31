use std::sync::OnceLock;

use suricata_ffi::{
    flow::{self, Flow, Packet, ThreadVars},
    SCLogError, SCLogNotice,
};
use suricata_sys::sys::FlowStorageId;

use crate::thread::{ExampleThreadStorage, THREAD_STORAGE_ID};

#[derive(Debug, Default)]
pub(crate) struct ExampleFlowStorage {
    pub(crate) packets_seen: usize,
}

pub(crate) static FLOW_STORAGE_ID: OnceLock<FlowStorageId> = OnceLock::new();

pub(crate) fn register() -> Result<(), &'static str> {
    let storage_id = flow::storage::register::<ExampleFlowStorage>("foo")?;
    FLOW_STORAGE_ID
        .set(storage_id)
        .map_err(|_| "Flow storage already registered")?;

    flow::register_init_callback(|tv: *mut ThreadVars, f: *mut Flow, p: *const Packet| {
        SCLogNotice!(
            "Flow init callback (tv={:p}, flow={:p}, packet={:p})",
            tv,
            f,
            p
        );

        let Some(storage_id) = FLOW_STORAGE_ID.get().copied() else {
            SCLogError!("Flow storage id not available");
            return;
        };

        let storage = ExampleFlowStorage::default();
        if let Err(err) = unsafe { flow::storage::set_by_id(f, storage_id, storage) } {
            SCLogError!("Failed to set flow storage: {}", err);
        }
    })?;

    flow::register_update_callback(|tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet| {
        let thread_count = match get_thread_storage(tv) {
            Some(storage) => {
                storage.count += 1;
                Some(storage.count)
            }
            None => None,
        };

        let flow_packets = match get_flow_storage(f) {
            Some(storage) => {
                storage.packets_seen += 1;
                Some(storage.packets_seen)
            }
            None => None,
        };

        SCLogNotice!(
            "Flow update callback (tv={:p}, flow={:p}, packet={:p}, thread_count={:?}, flow_packets={:?})",
            tv,
            f,
            p,
            thread_count,
            flow_packets,
        );
    })?;

    flow::register_finish_callback(|tv: *mut ThreadVars, f: *mut Flow| {
        let flow_packets = get_flow_storage(f).map(|storage| storage.packets_seen);
        SCLogNotice!(
            "Flow finish callback (tv={:p}, flow={:p}, flow_packets={:?})",
            tv,
            f,
            flow_packets,
        );
    })?;

    Ok(())
}

fn get_thread_storage(tv: *mut ThreadVars) -> Option<&'static mut ExampleThreadStorage> {
    let id = THREAD_STORAGE_ID.get().copied()?;
    unsafe { suricata_ffi::thread::storage::get_by_id(tv, id) }
}

fn get_flow_storage(f: *mut Flow) -> Option<&'static mut ExampleFlowStorage> {
    let id = FLOW_STORAGE_ID.get().copied()?;
    unsafe { flow::storage::get_by_id(f, id) }
}
