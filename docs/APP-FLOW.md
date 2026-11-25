# Application Flow — WireScope

## 1. Application entry points

WireScope has two frontends over the shared C++ analysis engine:

- **Desktop GUI:** interactive packet inspection and live capture.
- **CLI:** command-line offline/live analysis and report export.

The GUI and CLI must not maintain separate protocol parsing implementations.

## 2. Desktop GUI user journey

```text
Launch WireScope
       |
       v
Main window
       |
       +-----------------------------+
       |                             |
       v                             v
Open capture file              Select interface
       |                             |
       v                             v
Read PCAP packets              Start live capture
       |                             |
       +-------------+---------------+
                     |
                     v
             Shared AnalysisEngine
                     |
                     v
                Packet table
                     |
          +----------+-----------+
          |          |           |
          v          v           v
    Select row   Apply filter  Statistics
          |
          v
   Packet inspection
          |
    +-----+----------------------+
    |             |              |
    v             v              v
Protocol tree   Hex/ASCII    Application metadata
                              |
                 +------------+-----------+
                 |            |           |
                 v            v           v
              TCP stream    DNS details  HTTP/TLS details
                 |
                 v
         Directional ASCII/hex views
```

## 3. Main window

### Capture controls

- Open classic Ethernet PCAP through a file dialog.
- Select a listed Linux network interface.
- Toggle promiscuous capture where supported.
- Start and stop live capture.
- Display capture state and errors.
- Keep all packet processing away from the GUI thread.

### Packet table

Each row represents one captured packet and should provide, where available:

- Packet number.
- Timestamp.
- Source and destination address.
- Protocol.
- Source and destination port.
- Length.
- Short information/summary.

The display filter applies to the current capture view. Filtering must not mutate or delete the underlying packet history.

### Selected packet inspection

Selecting a row updates:

1. The expandable protocol tree.
2. The raw hexadecimal/ASCII byte view.
3. Any available application-protocol context.

The details panel must clearly distinguish absent fields, parse errors and fields that are not decoded by the current implementation.

## 4. Analysis navigation

### TCP connections and streams

- The user opens the TCP connections view.
- Selecting or double-clicking a connection opens **Follow TCP Stream**.
- The stream view displays each direction separately.
- ASCII and hexadecimal representations are available.
- Stream counters and incomplete/pending data must be visible.
- Connection matching must account for connection generations and timestamps, not only the four-tuple, because TCP endpoint tuples can be reused.

### DNS

- DNS messages are associated with the packet that carried them.
- Selecting a DNS message should allow navigation back to its source packet.
- Display query/response state, transaction ID, questions, response code and decoded records when available.

### HTTP and TLS

- Application analysis is derived from reassembled directional TCP streams.
- Selecting an HTTP message or TLS ClientHello opens its metadata view.
- Display HTTP start line, headers, framing and completeness flags.
- Display TLS ClientHello version metadata, SNI, ALPN and cipher suites when present.
- Do not imply that encrypted TLS application data has been decrypted.

## 5. Statistics flow

The Statistics view summarizes the current capture:

- Total packets and wire bytes.
- Capture duration.
- Average packet rate and throughput.
- Protocol distribution.
- Top TCP conversations.
- Traffic timeline.

Statistics must derive from captured/decoded records and use explicit units. Missing data must not be replaced with invented values.

## 6. CLI flow

```text
Start CLI
   |
   +--> Read classic PCAP file
   |        or
   +--> Capture from Linux interface
   |
   v
Apply supported packet filter
   |
   v
Decode and analyze packets
   |
   v
Print packet/connection/protocol summaries
   |
   +--> Optional JSON export
   |
   +--> Optional CSV export
```

## 7. Error and empty states

The UI must handle these states explicitly:

- No capture loaded: show a useful empty state and available actions.
- Empty capture: show zero packets without errors.
- Unsupported PCAP datalink or format: explain what is unsupported.
- Interface disappeared or is unavailable: show the capture error and allow refresh/retry.
- Permission denied: explain that live packet capture requires the appropriate Linux capability/privilege; do not automatically relaunch with elevated privileges.
- Invalid display filter: show the parser error without clearing the packet list.
- Malformed packet or protocol message: preserve the packet and show a decode/parse warning.
- Capture stopped: preserve the captured data and statistics.

## 8. Planned wireless flow

**Not implemented yet.** When Wi-Fi monitor support is added:

```text
Choose an existing monitor-mode interface
                 |
                 v
          Start wireless capture
                 |
                 v
       Detect capture datalink type
                 |
          +------+------+
          |             |
          v             v
       Ethernet     Radiotap/802.11
          |             |
          v             v
    Ethernet decoder  Wireless decoder
          |             |
          +------+------+
                 |
                 v
      Shared packet model and GUI
                 |
       +---------+----------+
       |                    |
       v                    v
  Wireless details     Wireless statistics
```

A user-created monitor interface may be selected. WireScope must not silently alter the active managed Wi-Fi interface, disconnect the user or change channels without explicit consent.
