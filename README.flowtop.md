# Suricata flowtop plugin example

`flowtop` is an example Suricata plugin that hooks into the flow lifecycle. It
tracks active flows, flow counts, byte counters, packet counters, approximate
bandwidth, and app-protocol, then publishes live snapshots over a Unix stream
socket.

It includes two clients:

- a terminal `ratatui` top-like view
- a browser-based graphical “Flow City” visualizer

## Build the plugin

From a configured Suricata source/build tree:

```sh
cd examples/plugins/flowtop
make
```

This creates:

```text
examples/plugins/flowtop/flowtop.so
```

## Run Suricata with flowtop

The plugin defaults to:

```text
/tmp/suricata-flowtop.sock
```

Override it with `SURICATA_FLOWTOP_SOCKET` if desired:

```sh
SURICATA_FLOWTOP_SOCKET=/tmp/suricata-flowtop.sock \
  ./src/suricata --plugin ./examples/plugins/flowtop/flowtop.so -c suricata.yaml -i eth0
```

For pcap testing:

```sh
SURICATA_FLOWTOP_SOCKET=/tmp/suricata-flowtop.sock \
  ./src/suricata --plugin ./examples/plugins/flowtop/flowtop.so -c suricata.yaml -r traffic.pcap
```

The socket emits newline-delimited JSON snapshots. Each line is a complete
snapshot with aggregate counters and currently active flows.

## Terminal UI

```sh
cd examples/plugins/flowtop/tui
cargo run -- /tmp/suricata-flowtop.sock
```

Or use the environment variable:

```sh
SURICATA_FLOWTOP_SOCKET=/tmp/suricata-flowtop.sock cargo run
```

Keys:

- `q` or `Esc`: quit

The TUI sorts active flows by current bandwidth, then total bytes.

## Web graphical UI: Flow City

Browsers cannot connect to Unix sockets directly, so the web UI includes a tiny
Rust HTTP/SSE bridge. It reads from the flowtop Unix socket and streams snapshots
to the browser.

Start the bridge:

```sh
cd examples/plugins/flowtop/web
cargo run -- --socket /tmp/suricata-flowtop.sock --listen 127.0.0.1:9876
```

Open:

```text
http://127.0.0.1:9876
```

In Flow City:

- each IP address becomes a building
- new IPs rise into the skyline
- active flows become neon beams between buildings
- beam thickness/color follows flow bandwidth

## Socket data format

The plugin publishes newline-delimited JSON. Example shape:

```json
{
  "type": "flowtop",
  "version": 1,
  "timestamp_ms": 1760000000000,
  "active_flows": 2,
  "total_flows": 10,
  "closed_flows": 8,
  "total_bytes": 123456,
  "total_bps": 42000,
  "flows": [
    {
      "id": 123,
      "src_ip": "192.0.2.10",
      "dest_ip": "198.51.100.20",
      "src_port": 51514,
      "dest_port": 443,
      "proto": "TCP",
      "app_proto": "tls",
      "packets": 30,
      "bytes": 22000,
      "bps": 12000,
      "age_ms": 8000
    }
  ]
}
```

## Notes

- Flows disappear from the UIs when Suricata closes or expires them.
- `closed_flows` increments when flows are removed from the active list.
- The bandwidth value is approximate and calculated from flow byte deltas.
- If the web UI says connected but does not animate, confirm Suricata is seeing
  active flows and that the bridge is pointed at the same socket path.
