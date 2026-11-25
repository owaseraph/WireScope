# Core source instructions

- Core libraries and headers must remain independent of Qt.
- Keep the CLI as a frontend; reusable packet/capture/analysis behavior belongs in focused libraries.
- Treat packet data as hostile input. Bounds-check all reads and validate nested lengths before parsing.
- Keep datalink type explicit. Never feed non-Ethernet data into `decode_ethernet`.
- Prefer pure parser functions over hidden global state. Return explicit parse errors or typed failure states where appropriate.
- Preserve timestamps, wire length, captured length and original bytes when useful to downstream analysis.
- Keep memory use bounded for reassembly and any new long-lived buffers. Document and test limits.
- Add deterministic parser/unit tests for every new packet structure. No live network or root requirement in unit tests.
