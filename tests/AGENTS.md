# Test-specific instructions

- Tests must be deterministic and must not require external network access, root privileges or physical network hardware.
- Prefer handcrafted packet bytes for boundary and malformed-input cases; use small synthetic PCAP fixtures for end-to-end ingestion.
- Assert meaningful decoded fields and failure behavior, not only that parsing returned successfully.
- Include truncated headers, inconsistent lengths, invalid offsets, unsupported values and boundary conditions where relevant.
- Keep demo captures under `fixtures/`; never add personal traffic captures or secrets.
- Keep test assertions active in Release builds (the current CMake test setup explicitly undefines `NDEBUG` for test targets).
- Follow `docs/TESTING-GUIDE.md` for commands and the completion checklist.
