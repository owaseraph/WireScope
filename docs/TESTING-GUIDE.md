# Testing Guide — WireScope

## 1. Testing goals

WireScope processes untrusted packet bytes and must remain safe with malformed, truncated and unusual inputs. Tests should verify both decoded results and failure behavior.

Favor deterministic tests that run offline and do not require root, a live network, a Wi-Fi adapter or an external server.

## 2. Build configurations

### Release build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

### Debug build

```bash
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug -j"$(nproc)"
ctest --test-dir build-debug --output-on-failure
```

### AddressSanitizer and UndefinedBehaviorSanitizer

```bash
cmake -S . -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DWIRESCOPE_ENABLE_SANITIZERS=ON
cmake --build build-asan -j"$(nproc)"
ctest --test-dir build-asan --output-on-failure
```

Qt is optional. If `qt6-base` is installed, CMake should configure `wirescope-gui`; otherwise the CLI and core should still build. For GUI work, ensure CMake actually reports that the GUI target is enabled, then build and launch it rather than treating a CLI-only build as GUI verification.

## 3. Current automated test targets

CMake currently registers seven CTest executables:

| Test | Responsibility |
|---|---|
| `decoder_tests` | Ethernet/VLAN/IP/transport decoding and malformed packet behavior |
| `tcp_tests` | TCP analysis behavior |
| `http_tests` | HTTP parser behavior |
| `dns_tests` | DNS parser behavior |
| `tls_tests` | TLS ClientHello parser behavior |
| `analysis_engine_tests` | End-to-end ingestion using bundled captures and display-filter checks |
| `pcap_io_tests` | Classic PCAP link-type preservation |

Other test source files may exist in `tests/`, but files not referenced by the CMake test setup are not built or run by the standard CTest commands above. There is currently no automated GUI test target. GUI verification is covered by the manual checklist below.

Run one focused test by name:

```bash
ctest --test-dir build -R analysis_engine_tests --output-on-failure
```

Run all tests before completing a feature milestone or preparing a release:

```bash
ctest --test-dir build --output-on-failure
```

Do not change a test to make it pass by weakening meaningful assertions. Do not rely only on successful compilation for parser changes.

## 4. Bundled fixtures

Fixtures are stored in `fixtures/` and are safe synthetic examples:

- `dns-demo.pcap`: DNS A query and response.
- `http-demo.pcap`: HTTP request/response.
- `tls-clienthello-demo.pcap`: ClientHello with SNI and ALPN metadata.

Regenerate using:

```bash
python tools/generate_demo_pcaps.py
```

The original development captures `tcp-test.pcap` and `ipv6-loopback.pcap` are user-local fixtures and may not be present in a clean checkout. Never fabricate a claim that those captures were tested if they were unavailable.

## 5. Manual CLI smoke checks

```bash
./build/wirescope --help
./build/wirescope fixtures/dns-demo.pcap --export-json /tmp/wirescope-dns.json
./build/wirescope fixtures/http-demo.pcap --export-json /tmp/wirescope-http.json
./build/wirescope fixtures/tls-clienthello-demo.pcap --export-json /tmp/wirescope-tls.json
```

Validate JSON syntax with:

```bash
python -m json.tool /tmp/wirescope-dns.json >/dev/null
python -m json.tool /tmp/wirescope-http.json >/dev/null
python -m json.tool /tmp/wirescope-tls.json >/dev/null
```

If `tcp-test.pcap` and `ipv6-loopback.pcap` are present locally, also test them. Expected historical characteristics are documented in the project's development notes/README; verify packet counts and protocol behavior against the actual files.

## 6. GUI manual smoke checklist

With Qt 6 Widgets installed and `wirescope-gui` built:

- [ ] Launch the GUI without a capture loaded; verify a useful empty state.
- [ ] Open each bundled PCAP fixture.
- [ ] Confirm packet rows are displayed and selection changes the protocol tree and hex view.
- [ ] Select a malformed/unknown packet if a fixture is available; verify graceful error presentation.
- [ ] Follow a TCP stream from a connection and from a packet context menu when the capture contains TCP payload.
- [ ] Inspect both stream directions and compare byte counts with the reassembled data.
- [ ] Open DNS details and navigate to the packet that contained the DNS message.
- [ ] Open HTTP/TLS details where the selected capture contains those protocols.
- [ ] Check protocol distribution, top conversations and traffic timeline.
- [ ] Apply a valid display filter, then an invalid one; invalid input must not destroy the capture.
- [ ] Start and stop live capture on a permitted Linux interface; verify the window remains responsive.
- [ ] Close the window during or immediately after capture; verify the worker stops safely.

Live capture permission checks must be performed by the developer. Do not add automatic privilege escalation to the test suite.

Current implementation note: capture reads run in a worker thread, but packet ingestion, decoding, and analysis run on the GUI thread when delivered packets are handled. The live-capture checklist is a manual responsiveness check; it does not imply that all packet processing is off-thread.

The analysis-engine tests also cover Ethernet routing and safe retention of unsupported link types. These checks are synthetic and require no capture privileges.

## 7. Planned wireless test requirements (not implemented)

Wireless parser tests must be handcrafted and deterministic:

- Radiotap base header and variable-length present bitmap.
- Radiotap field alignment and bounds checks.
- Unknown/unsupported Radiotap fields.
- Truncated Radiotap headers.
- IEEE 802.11 frame control parsing.
- Management, control and data frame classification.
- Address/BSSID selection for relevant frame types.
- SSID information-element parsing, including hidden/empty SSIDs.
- Channel/frequency and signal strength where metadata exists.
- Malformed information-element lengths and truncated frames.
- Correct routing by datalink type (Ethernet vs Radiotap); never decode Radiotap bytes as Ethernet.

These tests must not require a monitor-mode adapter, root, an access point or live radio traffic.

Monitor-mode capture is planned to use an already configured monitor interface. Tests and application workflows must not automatically change interface mode or channel.

## 8. Completion criteria

A feature is not complete until:

1. The affected targets compile with the repository warning flags.
2. Focused tests pass.
3. The complete CTest suite passes at the milestone/release boundary.
4. Relevant CLI/GUI manual smoke checks are done or clearly marked not run.
5. Documentation describes actual behavior and known limitations.
6. The final summary names exact commands and reports any unverified configuration.
