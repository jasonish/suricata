use suricata_ffi::{
    flow::{self, Flow, Packet, ThreadVars},
    SCLogNotice,
};

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
            p
        );
    })?;

    flow::register_finish_callback(|tv: *mut ThreadVars, f: *mut Flow| {
        SCLogNotice!("Flow finish callback (tv={:p}, flow={:p})", tv, f);
    })?;

    Ok(())
}
