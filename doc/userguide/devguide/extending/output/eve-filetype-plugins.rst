EVE/JSON File Type Plugins
###########################

Introduction
************

The Suricata EVE/JSON output supports custom filetypes with plugins. A
custom filetype plugin can be used as an alternative to writing to a
file. This is done by using a plugin that implements a file-like
interface to Suricata, but could send events to a database, a socket,
or even do some custom processing on the output and then write it to a
file.

EVE File Type Life Cycle
************************

The life-cycle of an EVE plugin along with the callbacks are discussed
in ``output-eve.h``:

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Structure used to define an EVE output
   :end-at: } SCEveFileType;

Threading Considerations
************************

It is the users Suricata EVE output configuration that enabled
multi-threaded logging, not the plugin. So all plugins should be
designed to be thread safe.

If your plugin can absolutely not be made thread safe, it would be
best to error out on initialization, this can be done during the file
type initialization:

.. code-block:: c

   static int MyFiletypeInit(const SCConfNode *node, const bool threaded, void **data)
   {
       if (threaded) {
           FatalError("EVE file type does not support threaded logging.");
       }

       /* Continue with initialization. */
   }

Write Considerations
********************

The ``Write`` callback is called in a packet processing thread so any
blocking (other than writing to a file) should be avoided. If writing
to a blocking resource it is recommended to copy the buffer into
another thread for further processing to avoid packet loss.
