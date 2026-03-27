mod eve;
mod thread;

use suricata_ffi::{SCLogError, SCLogNotice};
use suricata_sys::sys::SCPlugin;

unsafe extern "C" fn init() {
    suricata_ffi::plugin::init();
    SCLogNotice!("Initializing rust example plugin");

    if let Err(err) = eve::register() {
        SCLogError!("Failed to register rust example EVE callback: {}", err);
    }
    if let Err(err) = thread::register() {
        SCLogError!(
            "Failed to register rust example thread init callback: {}",
            err
        );
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *mut SCPlugin {
    suricata_ffi::plugin::Plugin {
        name: "rust",
        version: env!("CARGO_PKG_VERSION"),
        license: "MIT",
        author: "Open Information Security Foundation",
        init,
    }
    .into_raw()
}
