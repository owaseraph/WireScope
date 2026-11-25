# Implementation Plan — WireScope

This is the project roadmap and working sequence. Update status as work is merged. Do not mark a phase complete merely because code has been drafted; require build/test evidence.

## Current baseline

The current baseline contains the C++20 CLI, optional Qt 6 Widgets GUI, Ethernet PCAP/live capture, TCP tracking/reassembly, HTTP/1.x, DNS/mDNS over UDP, TLS ClientHello metadata, stream inspection and statistics. The GUI uses `AnalysisEngine`; the CLI has its own processing context and orchestration while reusing the shared decoder, TCP, and protocol libraries. GUI capture reads run in a worker thread, but packet ingestion, decoding, and analysis currently run on the GUI thread.

Check the current GitHub head before starting a task; branch and commit names in older notes can become stale.

## Engineering rules for every phase

- Start from an up-to-date `develop` branch and use one feature branch per cohesive feature.
- Inspect working-tree status before switching branches. Preserve any local work.
- Review current code and tests before designing interfaces.
- Keep the core independent of Qt.
- Prefer small, testable modules with clear value types and explicit ownership.
- Add parser tests using handcrafted bytes; avoid requiring privileged network access.
- Keep CLI functionality working when Qt is unavailable.
- Update `TECHNICAL-REQUIREMENTS.md`, `APP-FLOW.md` and `TESTING-GUIDE.md` if behavior or user journeys change.
- Run targeted checks after each meaningful change and the full suite before completing a milestone.

## Phase 1 — Wi-Fi capture and datalink-aware architecture

**Status: Planned**  
**Suggested branch:** `feat/wifi-monitor-mode`

### Goal

Add wireless packet capture from a monitor-mode interface without breaking existing Ethernet capture or decoding.

### Work sequence

1. Introduce explicit datalink metadata at capture and packet boundaries. `CapturedPacket` currently has no datalink field; do not infer link type from frame bytes.
2. Keep separate Ethernet and wireless decoding routes. Preserve current Ethernet PCAP behavior and never pass Radiotap or raw 802.11 frames to `decode_ethernet`.
3. Implement Radiotap parsing as a dedicated core parser, including variable present bitmaps, field alignment, bounds checks, and safe handling of unknown fields. Test it independently.
4. Add focused IEEE 802.11 decoding: frame control and type/subtype, address roles for covered frame types, and management information elements such as SSID. Represent unavailable or ambiguous fields explicitly.
5. Integrate datalink-aware capture and wireless metadata through shared core APIs. Resolve how the Linux live-capture source reports the actual delivered link type; do not assume `AF_PACKET` provides this from packet bytes.
6. Add GUI presentation for wireless metadata and improve processing performance. The current GUI ingests and analyzes delivered packets on its GUI thread, so include a design for keeping high-rate capture responsive.
7. Add deterministic synthetic parser and routing tests that need no hardware or privileges, followed by fixture-based regression checks and CLI/Qt-enabled build verification.
8. Update documentation only to describe behavior implemented and verified. Keep implemented features, current limitations, and planned work clearly separated.

### Acceptance criteria

- Existing Ethernet packet decoding and all current PCAP fixtures remain unchanged.
- Radiotap is never passed to `decode_ethernet`.
- Unknown/unsupported datalink types fail with a clear message instead of being mis-decoded.
- Truncated or malformed Radiotap/802.11 frames do not crash the application.
- Management, control and data frames are classified correctly for the covered frame types.
- BSSID and transmitter/receiver addresses are selected according to frame type, with ambiguous/unknown values represented honestly.
- SSID, frequency/channel and signal strength are shown only when present and valid.
- Capture initially uses an already configured monitor interface. WireScope does not automatically change interface mode or channel.
- GUI and CLI continue to build; all existing tests pass plus new wireless tests.

### Risks to resolve before coding

- Linux monitor interfaces may deliver different link types depending on driver and interface configuration.
- Radiotap fields have alignment rules and a variable present bitmap; do not assume a fixed header size.
- Some drivers omit metadata or expose channel/frequency information differently.
- Wireless frame address semantics vary by To DS / From DS and frame subtype.
- Monitor mode generally requires a separate interface/configuration and can disrupt connectivity if users alter their active interface.

## Phase 2 — Wireless GUI workflows

**Status: Planned; may be delivered with Phase 1 if scope remains manageable.**

- Clearly distinguish Ethernet and Wi-Fi capture sources.
- Show frame type/subtype, BSSID, transmitter, receiver, SSID and available Radiotap metadata.
- Add wireless protocol distribution and top observed BSSID statistics.
- Provide a concise warning when a frame type is unsupported or metadata is unavailable.
- Keep wireless-specific columns optional/configurable so Ethernet views remain readable.

## Phase 3 — Product hardening

**Status: Planned.**

- Review capture-history memory growth; add a configurable bounded packet retention policy for long-running live captures.
- Add GUI tests for model updates, selection, filtering, stream dialogs and worker shutdown where practical.
- Improve PCAPNG support and multi-datalink capture only after the datalink abstraction is stable.
- Improve filter grammar while preserving clear, testable semantics.
- Add packaging/install targets and application metadata for Linux desktop distribution.

## Phase 4 — Further protocol coverage

**Status: Backlog.**

Candidates, in priority order after wireless foundation:

1. DNS over TCP with correct two-byte message-length framing and stream reassembly.
2. Better HTTP request/response correlation (including HEAD and informational response handling).
3. TLS handshake/certificate metadata where visible without decryption.
4. Additional protocol dissectors selected based on actual user needs and testable captures.

Do not add protocol names to the feature list until the parser and integration exist.

## Working agreement for agents

At the start of a milestone, report the files/interfaces inspected, the design risks and a concise task plan. Then implement the coherent milestone; do not stop after producing only a plan. Before finishing, report changed files, commands run, test results, platform/hardware checks not run, known limitations and any follow-up needed.
