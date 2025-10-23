EVE/JSON File Type Plugins
###########################

Introduction
************

EVE (Extensible Event Format) file type plugins allow developers to
create custom outputs for Suricata's JSON event logs. These plugins
provide a file-like interface for handling formatted JSON log records
and can output to various destinations such as files, databases,
message queues, or network services.

File type plugins are particularly useful for:

- Custom log destinations not built into Suricata
- Post-processing of JSON records before writing
- Integrating with external systems and APIs
- Implementing custom buffering or batching strategies

Suricata provides both C and Rust APIs for creating EVE file type plugins.

Plugin Architecture Overview
*****************************

EVE file type plugins implement a file-like interface with the following lifecycle:

1. **Plugin Registration**: The plugin registers itself with Suricata via ``SCPluginRegister()``
2. **Plugin Initialization**: Suricata calls the plugin's ``Init`` callback
3. **Filetype Registration**: The plugin registers its file type handler
4. **Instance Initialization**: ``Init`` callback is called for each EVE instance using this filetype
5. **Thread Initialization**: ``ThreadInit`` is called for each output thread (if threaded mode)
6. **Write Operations**: ``Write`` is called for each JSON log record
7. **Thread Cleanup**: ``ThreadDeinit`` is called for each thread on shutdown
8. **Instance Cleanup**: ``Deinit`` is called for each EVE instance on shutdown

Threading Considerations
========================

The EVE logging system can operate in two modes:

**Non-threaded Mode** (default):
  - ``ThreadInit`` is called once with thread_id = 0
  - Plugin does not need to be thread-aware
  - Single output stream

**Threaded Mode**:
  - ``ThreadInit`` is called multiple times, once per output thread
  - Plugin must be thread-safe
  - Each thread typically gets a unique thread_id
  - Plugins should either use separate resources per thread (files, connections) or implement proper locking

.. warning::

   Do not block in the ``Write`` callback as this will cause packet loss. If
   writing to a potentially slow resource (network, database), consider using an
   internal queue with a background thread.

C API for JSON File Type Plugins
*********************************

Plugin Registration
===================

Every Suricata plugin must export a ``SCPluginRegister`` function that returns
a pointer to an ``SCPlugin`` structure:

.. code-block:: c

    #include "suricata-plugin.h"

    static void PluginInit(void);

    const SCPlugin PluginRegistration = {
        .version = SC_API_VERSION,
        .suricata_version = SC_PACKAGE_VERSION,
        .name = "my-json-output",
        .plugin_version = "0.1.0",
        .author = "Your Name <your.email@example.com>",
        .license = "GPL-2.0-only",
        .Init = PluginInit,
    };

    const SCPlugin *SCPluginRegister()
    {
        return &PluginRegistration;
    }

SCEveFileType Structure
=======================

The ``SCEveFileType`` structure defines the callbacks for your file type plugin:

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: typedef struct SCEveFileType_
   :end-at: } SCEveFileType;

Lifecycle Functions
===================

Init Function
-------------

Called once for each EVE instance using this file type:

.. code-block:: c

    static int MyFiletypeInit(const SCConfNode *conf, const bool threaded, void **data)
    {
        // Allocate context structure
        MyContext *context = SCCalloc(1, sizeof(MyContext));
        if (context == NULL) {
            return -1;
        }

        // Read configuration from conf node
        if (conf != NULL) {
            SCConfNode *plugin_conf = SCConfNodeLookupChild(conf, "my-config");
            if (plugin_conf != NULL) {
                // Parse plugin-specific configuration
            }
        }

        // Store context
        *data = context;
        return 0;
    }

ThreadInit Function
-------------------

Called once for each output thread:

.. code-block:: c

    static int MyFiletypeThreadInit(const void *ctx, const ThreadId thread_id,
                                     void **thread_data)
    {
        MyThreadContext *tdata = SCCalloc(1, sizeof(MyThreadContext));
        if (tdata == NULL) {
            return -1;
        }

        tdata->thread_id = thread_id;
        // Initialize thread-specific resources (connections, files, etc.)

        *thread_data = tdata;
        return 0;
    }

Write Function
--------------

Called for each JSON log record:

.. code-block:: c

    static int MyFiletypeWrite(const char *buffer, const int buffer_len,
                                const void *data, void *thread_data)
    {
        const MyContext *ctx = data;
        MyThreadContext *tctx = thread_data;

        // Write the buffer (already formatted JSON)
        // buffer is null-terminated but buffer_len provides the length

        // Return 0 on success, -1 on failure
        return 0;
    }

.. warning::
   The ``Write`` function must not block! If writing to a slow resource, use a queue and background thread.

ThreadDeinit Function
---------------------

Called for each thread on shutdown:

.. code-block:: c

    static void MyFiletypeThreadDeinit(const void *ctx, void *thread_data)
    {
        if (thread_data == NULL) {
            return;
        }

        MyThreadContext *tdata = thread_data;
        // Clean up thread-specific resources
        SCFree(tdata);
    }

Deinit Function
---------------

Called once for each EVE instance on shutdown:

.. code-block:: c

    static void MyFiletypeDeinit(void *data)
    {
        if (data == NULL) {
            return;
        }

        MyContext *ctx = data;
        // Clean up context resources
        SCFree(ctx);
    }

Registering the File Type
==========================

In your plugin's ``Init`` callback, register the file type:

.. code-block:: c

    static void PluginInit(void)
    {
        SCEveFileType *my_output = SCCalloc(1, sizeof(SCEveFileType));
        my_output->name = "my-json-output";
        my_output->Init = MyFiletypeInit;
        my_output->Deinit = MyFiletypeDeinit;
        my_output->ThreadInit = MyFiletypeThreadInit;
        my_output->ThreadDeinit = MyFiletypeThreadDeinit;
        my_output->Write = MyFiletypeWrite;

        if (!SCRegisterEveFileType(my_output)) {
            FatalError("Failed to register filetype plugin: %s", my_output->name);
        }
    }

Complete C Example
==================

See the complete working example at:
``examples/plugins/c-json-filetype/filetype.c``

Rust API for JSON File Type Plugins
************************************

Rust plugins use FFI (Foreign Function Interface) to interact with Suricata's C API. The ``suricata`` and ``suricata-sys`` crates provide the necessary bindings.

Dependencies
============

Add these dependencies to your ``Cargo.toml``:

.. code-block:: toml

    [package]
    name = "my-redis-output"
    version = "0.1.0"
    edition = "2021"

    [lib]
    crate-type = ["cdylib"]

    [dependencies]
    suricata = "0.7"
    suricata-sys = "0.7"

Plugin Registration
===================

Export the ``SCPluginRegister`` function using ``#[no_mangle]``:

.. code-block:: rust

    use std::ffi::CString;
    use std::os::raw::c_char;
    use suricata_sys::sys::{SCPlugin, SC_API_VERSION, SC_PACKAGE_VERSION};

    unsafe extern "C" fn init_plugin() {
        // Register file type here
    }

    #[no_mangle]
    extern "C" fn SCPluginRegister() -> *const SCPlugin {
        // Initialize Suricata plugin system
        suricata::plugin::init();

        let plugin_version = CString::new(env!("CARGO_PKG_VERSION"))
            .unwrap()
            .into_raw() as *const c_char;

        let plugin = SCPlugin {
            version: SC_API_VERSION,
            suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const c_char,
            name: b"my-output\0".as_ptr() as *const c_char,
            plugin_version,
            license: b"MIT\0".as_ptr() as *const c_char,
            author: b"Your Name\0".as_ptr() as *const c_char,
            Init: Some(init_plugin),
        };

        Box::into_raw(Box::new(plugin))
    }

FFI Bindings
============

Create FFI type definitions for the C callbacks:

.. code-block:: rust

    use std::os::raw::{c_char, c_int, c_void};

    pub type InitFn = unsafe extern "C" fn(
        conf: *const c_void,
        threaded: bool,
        init_data: *mut *mut c_void,
    ) -> c_int;

    pub type DeinitFn = unsafe extern "C" fn(init_data: *const c_void);

    pub type WriteFn = unsafe extern "C" fn(
        buffer: *const c_char,
        buffer_len: c_int,
        init_data: *const c_void,
        thread_data: *const c_void,
    ) -> c_int;

    pub type ThreadInitFn = unsafe extern "C" fn(
        init_data: *const c_void,
        thread_id: c_int,
        thread_data: *mut *mut c_void,
    ) -> c_int;

    pub type ThreadDeinitFn = unsafe extern "C" fn(
        init_data: *const c_void,
        thread_data: *mut c_void,
    );

    #[repr(C)]
    pub struct SCEveFileType {
        pub name: *const c_char,
        pub open: InitFn,
        pub thread_init: ThreadInitFn,
        pub write: WriteFn,
        pub thread_deinit: ThreadDeinitFn,
        pub close: DeinitFn,
        pad: [usize; 2],
    }

    extern "C" {
        pub fn SCRegisterEveFileType(filetype: *const SCEveFileType) -> bool;
    }

Implementing Callbacks
======================

Implement the callback functions in Rust:

.. code-block:: rust

    use suricata::conf::ConfNode;
    use suricata_sys::sys::SCConfNode;
    use suricata::{SCLogNotice, SCLogError};

    struct Context {
        // Your context data
    }

    struct ThreadContext {
        thread_id: usize,
        // Thread-specific data
    }

    unsafe extern "C" fn output_init(
        conf: *const c_void,
        _threaded: bool,
        init_data: *mut *mut c_void,
    ) -> c_int {
        // Parse configuration
        let config = if conf.is_null() {
            Default::default()
        } else {
            let conf_node = ConfNode::wrap(conf as *const SCConfNode);
            // Parse your configuration
            Default::default()
        };

        // Create context
        let context = Box::new(Context {
            // Initialize fields
        });

        *init_data = Box::into_raw(context) as *mut _;
        0
    }

    unsafe extern "C" fn output_close(init_data: *const c_void) {
        let context = Box::from_raw(init_data as *mut Context);
        // Cleanup happens automatically when Box is dropped
    }

    unsafe extern "C" fn output_thread_init(
        init_data: *const c_void,
        thread_id: c_int,
        thread_data: *mut *mut c_void,
    ) -> c_int {
        let context = &*(init_data as *const Context);

        let thread_context = Box::new(ThreadContext {
            thread_id: thread_id as usize,
            // Initialize thread data
        });

        *thread_data = Box::into_raw(thread_context) as *mut _;
        0
    }

    unsafe extern "C" fn output_thread_deinit(
        _init_data: *const c_void,
        thread_data: *mut c_void,
    ) {
        let thread_context = Box::from_raw(thread_data as *mut ThreadContext);
        SCLogNotice!("Thread {} finished", thread_context.thread_id);
    }

    unsafe extern "C" fn output_write(
        buffer: *const c_char,
        buffer_len: c_int,
        _init_data: *const c_void,
        thread_data: *const c_void,
    ) -> c_int {
        let thread_context = &mut *(thread_data as *mut ThreadContext);

        // Convert C string to Rust string
        let buf = if let Ok(buf) = str_from_c_parts(buffer, buffer_len) {
            buf
        } else {
            return -1;
        };

        // Process the JSON buffer

        0
    }

    // Helper function to convert C string to Rust &str
    fn str_from_c_parts<'a>(
        buffer: *const c_char,
        buffer_len: c_int,
    ) -> Result<&'a str, std::str::Utf8Error> {
        unsafe {
            std::ffi::CStr::from_bytes_with_nul_unchecked(
                std::slice::from_raw_parts(
                    buffer as *const u8,
                    buffer_len as usize + 1,
                )
            ).to_str()
        }
    }

Registering the File Type
==========================

.. code-block:: rust

    unsafe extern "C" fn init_plugin() {
        let file_type = SCEveFileType {
            name: b"my-output-plugin\0".as_ptr() as *const c_char,
            open: output_init,
            close: output_close,
            write: output_write,
            thread_init: output_thread_init,
            thread_deinit: output_thread_deinit,
            pad: [0, 0],
        };

        let file_type_ptr = Box::into_raw(Box::new(file_type));
        SCRegisterEveFileType(file_type_ptr);
    }

Handling Blocking Operations
=============================

For plugins that write to potentially slow resources (networks, databases), use a channel and background thread:

.. code-block:: rust

    use std::sync::mpsc::{SyncSender, TrySendError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, JoinHandle};

    struct Context {
        tx: SyncSender<String>,
        th: JoinHandle<()>,
        done: Arc<AtomicBool>,
    }

    struct ThreadContext {
        thread_id: usize,
        tx: SyncSender<String>,
    }

    unsafe extern "C" fn output_init(
        conf: *const c_void,
        _threaded: bool,
        init_data: *mut *mut c_void,
    ) -> c_int {
        let (tx, rx) = std::sync::mpsc::sync_channel(1000);
        let done = Arc::new(AtomicBool::new(false));

        // Spawn background thread to handle writes
        let done_clone = done.clone();
        let th = thread::spawn(move || {
            while !done_clone.load(Ordering::Relaxed) {
                if let Ok(msg) = rx.recv() {
                    // Write to slow resource
                }
            }
        });

        let context = Box::new(Context { tx, th, done });
        *init_data = Box::into_raw(context) as *mut _;
        0
    }

    unsafe extern "C" fn output_write(
        buffer: *const c_char,
        buffer_len: c_int,
        _init_data: *const c_void,
        thread_data: *const c_void,
    ) -> c_int {
        let thread_context = &mut *(thread_data as *mut ThreadContext);
        let buf = str_from_c_parts(buffer, buffer_len).unwrap();

        // Non-blocking send
        if let Err(TrySendError::Full(_)) = thread_context.tx.try_send(buf.to_string()) {
            SCLogError!("Buffer full, dropping event");
        }

        0
    }

Complete Rust Example
=====================

See the complete working example at:
``https://github.com/jasonish/suricata-redis-output``

Building and Installing Plugins
********************************

C Plugins
=========

Building Standalone
-------------------

To build a C plugin outside the Suricata source tree:

1. Install Suricata development files:

   .. code-block:: bash

       make install-library
       make install-headers

2. Ensure ``libsuricata-config`` is in your PATH:

   .. code-block:: bash

       libsuricata-config --cflags

3. Build your plugin:

   .. code-block:: bash

       gcc -fPIC -shared $(libsuricata-config --cflags) \
           -o my-plugin.so my-plugin.c \
           $(libsuricata-config --libs)

Building Within Suricata Source
--------------------------------

If building within the Suricata source tree, use the provided Makefile templates in ``examples/plugins/``.

Rust Plugins
============

1. Build the plugin:

   .. code-block:: bash

       cargo build --release

2. The plugin library will be at ``target/release/libmyplugin.so``

Installing
==========

Copy the plugin to your plugins directory:

.. code-block:: bash

    mkdir -p /usr/local/lib/suricata/plugins
    cp my-plugin.so /usr/local/lib/suricata/plugins/

Configuration
*************

Loading the Plugin
==================

Add the plugin path to ``suricata.yaml``:

.. code-block:: yaml

    plugins:
      - /usr/local/lib/suricata/plugins/my-plugin.so

Configuring EVE Output
======================

Configure an EVE instance to use your plugin:

.. code-block:: yaml

    outputs:
      - eve-log:
          enabled: yes
          filetype: my-output-plugin  # Use the name from your plugin
          threaded: true
          types:
            - alert
            - dns
            - http
            - tls

          # Plugin-specific configuration
          my-config:
            option1: value1
            option2: value2

Multiple Instances
==================

You can have multiple EVE instances using the same or different file type plugins:

.. code-block:: yaml

    outputs:
      - eve-log:
          enabled: yes
          filetype: my-output-plugin
          types:
            - alert
            - http

      - eve-log:
          enabled: yes
          filetype: regular  # Built-in file output
          filename: standard.json
          types:
            - dns
            - tls

Best Practices
**************

Performance
===========

1. **Avoid Blocking**: Never block in the ``Write`` callback. Use queues and background threads for slow operations.

2. **Buffer Management**: Consider implementing batching to reduce write overhead:

   .. code-block:: c

       // Accumulate records in a buffer
       if (buffer_full || time_expired) {
           flush_buffer();
       }

3. **Connection Pooling**: For network-based outputs, maintain connection pools per thread to avoid connection overhead.

Error Handling
==============

1. **Graceful Degradation**: If the destination is unavailable, consider queuing events or logging errors rather than failing completely.

2. **Lost Event Tracking**: Track and report dropped events:

   .. code-block:: rust

       if send_fails {
           dropped_count += 1;
           SCLogError!("Dropped {} events", dropped_count);
       }

3. **Return Codes**: Always return appropriate values from callbacks:
   - Return 0 on success
   - Return -1 on failure

Thread Safety
=============

1. **Separate Resources**: Prefer separate resources per thread (files, connections) over shared resources with locking.

2. **Atomic Operations**: Use atomic operations for simple shared state:

   .. code-block:: rust

       use std::sync::atomic::{AtomicU64, Ordering};

       static TOTAL_EVENTS: AtomicU64 = AtomicU64::new(0);
       TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);

3. **Lock-Free Queues**: Consider lock-free queues like ``crossbeam`` for Rust or ``ck_ring`` for C.

Memory Management
=================

1. **C Plugins**: Use Suricata's memory functions (``SCCalloc``, ``SCMalloc``, ``SCFree``) for consistency with Suricata's memory tracking.

2. **Rust Plugins**: Use ``Box::into_raw()`` and ``Box::from_raw()`` for passing Rust data through C FFI.

3. **Cleanup**: Always clean up resources in ``ThreadDeinit`` and ``Deinit`` callbacks.

Configuration Parsing
=====================

1. **Provide Defaults**: Always provide sensible defaults for optional configuration:

   .. code-block:: c

       int timeout = 30;  // Default
       SCConfGetChildValueInt(conf, "timeout", &timeout);

2. **Validation**: Validate configuration values:

   .. code-block:: rust

       let port: u16 = conf.get_child_value("port")
           .and_then(|s| s.parse().ok())
           .unwrap_or(6379);

       if port == 0 {
           SCLogError!("Invalid port number");
           return -1;
       }

3. **Documentation**: Document all configuration options in your plugin's README.

Testing
=======

1. **Test Both Modes**: Test your plugin in both threaded and non-threaded modes.

2. **Load Testing**: Verify your plugin handles high throughput without dropping events.

3. **Failure Testing**: Test behavior when the destination is unavailable or slow.

4. **Memory Testing**: Use valgrind or similar tools to check for memory leaks.

Logging
=======

Use Suricata's logging functions to maintain consistent log formatting:

C:
    .. code-block:: c

        SCLogNotice("Plugin initialized");
        SCLogError("Connection failed: %s", error);
        SCLogDebug("Processing event %d", count);

Rust:
    .. code-block:: rust

        SCLogNotice!("Plugin initialized");
        SCLogError!("Connection failed: {}", error);

Troubleshooting
***************

Plugin Not Loading
==================

- Check the plugin path in ``suricata.yaml``
- Verify the plugin file has correct permissions
- Check Suricata logs for loading errors
- Ensure API version compatibility (``SC_API_VERSION``)

Events Not Appearing
====================

- Verify the ``filetype`` name matches the registered name
- Check that event types are configured correctly
- Review plugin logs for write errors
- Ensure the plugin's ``Write`` function returns 0

Performance Issues
==================

- Enable ``threaded: true`` in EVE configuration
- Check if the ``Write`` callback is blocking
- Monitor queue sizes if using background threads
- Use profiling tools to identify bottlenecks

Further Resources
*****************

- C Plugin Example: ``examples/plugins/c-json-filetype/``
- Rust Plugin Example: https://github.com/jasonish/suricata-redis-output
- Built-in Syslog Output: ``src/output-eve-syslog.c``
- Built-in Null Output: ``src/output-eve-null.c``
- Custom Loggers Example: ``examples/plugins/c-custom-loggers/``
- Suricata Plugin Documentation: https://docs.suricata.io/
