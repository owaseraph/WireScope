# WireScope — Agent Instructions

## Project mission

WireScope is a C++20 packet analyzer with a command-line frontend and an optional Qt 6 Widgets desktop frontend. Preserve both frontends and the shared analysis engine. The goal is a reliable, understandable packet analyzer—not a disposable demo or a rewrite on every feature.

Before making changes, read:

1. `TECHNICAL-REQUIREMENTS.md` for the current architecture, supported behavior, constraints and limitations.
2. `APP-FLOW.md` when changing GUI workflows or user-visible behavior.
3. `TESTING-GUIDE.md` for build, test and manual verification expectations.
4. `IMPLEMENTATION.md` for project priorities and the next planned milestone.

The repository documentation and source code are authoritative. If a document disagrees with the current code, inspect the code, explain the discrepancy and update the document when appropriate. Do not assume a planned feature already exists.

## Repository map

- `include/wirescope/`: public C++ interfaces.
- `src/`: packet decoding, capture I/O, analysis engine, protocol parsers and CLI.
- `gui/`: Qt Widgets frontend, capture worker, packet table, stream dialog and statistics.
- `tests/`: automated tests, including analysis-engine tests using bundled captures.
- `fixtures/`: small, safe-to-share demo PCAP files.
- `tools/`: fixture generation and development utilities.
- `CMakeLists.txt`: target definitions and optional dependencies.

## Architecture rules

- Keep packet analysis and capture-domain logic independent of Qt. `src/` and `include/wirescope/` must not include Qt headers or depend on Qt types.
- Keep the CLI (`src/main.cpp`) and GUI (`gui/`) as separate frontends over reusable core APIs.
- Prefer adding reusable behavior to a focused library/API over duplicating logic in either frontend.
- Preserve the current `AnalysisEngine` as the GUI-facing ingestion and analysis boundary unless a documented design change is justified.
- Treat captured packet bytes as untrusted input. Validate lengths, offsets, counts and integer conversions before accessing data.
- Keep link-layer format explicit. Do not pass Radiotap or raw IEEE 802.11 frames to the Ethernet decoder. A future wireless implementation must introduce datalink-aware capture/decoding while retaining Ethernet support.
- Preserve timestamps, capture lengths, wire lengths and packet identity when moving data between capture, analysis and UI layers.
- Avoid unbounded work on the GUI thread. Capture, expensive parsing and long-running operations must not freeze the UI.

## C++ coding standards

- Use C++20 and the existing CMake target structure.
- Follow the existing warning set: `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion` for GCC/Clang.
- Prefer RAII, value semantics, `std::span`, standard containers and explicit ownership.
- Avoid raw owning pointers, manual resource lifetimes, global mutable state and unnecessary abstractions.
- Keep functions focused and names descriptive. Prefer readable code over compressed one-line implementations.
- Handle malformed and truncated packets defensively. Never trust lengths found in packet data.
- Do not suppress compiler warnings just to get a build green. Fix the cause or document a narrowly justified exception.
- Do not add a production dependency without explaining why it is needed and how it affects the CLI-only build.

## Qt / GUI standards

- Use Qt 6 Widgets and the existing model/view approach for tabular packet data.
- Keep widgets responsible for presentation and interaction; put packet interpretation in the shared engine.
- Use Qt signals/slots or queued delivery for work crossing thread boundaries. Do not update widgets directly from a capture thread.
- Stop and join capture workers safely before destroying objects they can access.
- Do not block the GUI thread on capture reads, file I/O or expensive analysis.
- Make empty, malformed and incomplete analysis states visible instead of crashing or silently presenting fabricated values.
- Preserve keyboard accessibility, useful empty states, sensible resizing and clear status/error messages.

## Change workflow

1. Inspect `git status --short --branch` before editing. Never overwrite, reset or discard user changes.
2. Confirm the current branch and read the relevant implementation and tests.
3. For a feature spanning multiple modules, write a concise implementation plan and identify interfaces that must remain stable.
4. Implement in coherent increments. Avoid unrelated refactors in the same change.
5. Build the affected targets with the existing strict warnings.
6. Run focused tests for the changed behavior, then run the full CTest suite at feature completion or a milestone.
7. For packet-format work, include handcrafted tests that do not require root, network access or physical hardware. Add/update PCAP fixtures only when they are small and safe to commit.
8. Update the applicable requirements, app-flow, testing and implementation docs whenever behavior or scope changes.
9. Report exactly what changed, commands executed, test results, limitations and any checks not run.

## Git and safety boundaries

- Work on a dedicated feature branch created from the latest `develop` unless the user explicitly requests another workflow.
- Do not commit, push, open/merge a pull request, force-push, rewrite history or delete branches unless the user asks.
- Never run privileged capture or network-configuration commands without explicit user approval. Do not automatically change Wi-Fi mode, channels, NetworkManager state or interface configuration.
- Never commit personal PCAP captures, credentials, keys, environment files, generated build directories or analysis reports. Use only approved demo fixtures.
- Do not claim a build, GUI launch, test or hardware check passed unless it was actually run and its result observed.

## Definition of done

A change is done when its behavior is implemented, its public interfaces are coherent, relevant tests pass, the project still builds with the supported configurations, user-facing documentation is updated, and remaining limitations are stated honestly.
