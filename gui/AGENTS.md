# GUI-specific instructions

- Use Qt 6 Widgets and the existing `AnalysisEngine` API. Do not duplicate packet parsers in widgets.
- Keep `gui/` dependent on public `include/wirescope/` APIs; never make core `src/` depend on Qt.
- Keep UI updates on the GUI thread. Deliver capture-worker results through Qt signals/queued connections.
- Ensure workers are stopped and joined before destroying dependent state or widgets.
- Avoid full table reconstruction for every live packet; use the Qt model/view API and batched row updates.
- Preserve packet identity when applying display filters and when navigating from DNS/application records back to packets.
- Do not block the UI for file reads, packet capture or large stream rendering.
- Show incomplete, malformed and unavailable values explicitly. Never imply TLS decryption or metadata that is not in the capture.
- Keep dialogs usable for large captures; apply safe display limits and indicate when content is truncated.
- For GUI changes, follow the manual smoke checklist in `docs/TESTING-GUIDE.md`.
