# flowtop example plugin

`flowtop` demonstrates Suricata plugin flow lifecycle callbacks. It tracks active flows, packet/byte counters, and approximate bits-per-second per flow, then publishes snapshots over a Unix stream socket as newline-delimited JSON.

## Build

From a configured Suricata source/build tree:

```sh
cd examples/plugins/flowtop
make
```

## Run Suricata with the plugin

```sh
SURICATA_FLOWTOP_SOCKET=/tmp/suricata-flowtop.sock \
  suricata --plugin /path/to/examples/plugins/flowtop/flowtop.so ...
```

If `SURICATA_FLOWTOP_SOCKET` is not set, the plugin uses `/tmp/suricata-flowtop.sock`.

Each socket line is a full snapshot:

```json
{"type":"flowtop","version":1,"active_flows":1,"total_bps":1234,"flows":[...]}
```

## TUI client

```sh
cd examples/plugins/flowtop/tui
cargo run -- /tmp/suricata-flowtop.sock
```

Press `q` or `Esc` to quit.

## Web visualizer: Flow City

The web visualizer is a small Rust HTTP/SSE bridge plus a canvas UI. Browsers
cannot connect to Unix sockets directly, so the bridge connects to the flowtop
Unix socket and streams snapshots to the page using server-sent events.

```sh
cd examples/plugins/flowtop/web
cargo run -- --socket /tmp/suricata-flowtop.sock --listen 127.0.0.1:9876
```

Open `http://127.0.0.1:9876`.

In Flow City, each IP address becomes a building. New buildings rise into the
skyline as IPs appear, and glowing beams connect buildings for active flows.
Beam color/thickness follows flow bandwidth.
