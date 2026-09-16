# Third-Party Notices

offensive-claude incorporates technique content adapted from third-party sources. Their license terms
are reproduced/honored below. This file covers *adapted content*; offensive-claude's own license is in
[`LICENSE`](LICENSE).

---

## Claude-Red (SnailSploit)

- **Project:** Claude-Red — offensive-security skills for Claude
- **Upstream:** https://github.com/SnailSploit/Claude-Red
- **License:** MIT
- **Authors:** Kai Aizen (SnailSploit); derived in part from Sahar Shlichov's offensive-checklist collection.

**What we adapted:** technique methodology (not verbatim files) was used as a *seed* for the following,
then rewritten to this project's standards (technique-level ATT&CK + CWE, detection + OPSEC pairing,
evidence-bar/confidence discipline, `references/`+`scripts/` layout):

- `skills/wireless-rf/` — Bluetooth/BLE, Zigbee/Thread/Matter, Z-Wave, LoRaWAN/Sub-GHz references.
- `skills/network-attack/references/wireless-attacks.md` — KRACK/FragAttacks and WPS sections.
- `skills/web-pentest/references/business-logic-abuse.md` — business-logic abuse methodology.
- `skills/web-pentest/references/injection-sqli-cmdi.md` — HTTP Parameter Pollution and file-upload sections.
- `docs/COVERAGE-MAP.md` — coverage cross-reference idea (adapted from Claude-Red's `MINDMAP.md`).

### MIT License (Claude-Red)

```
MIT License

Copyright (c) 2024-2025 SnailSploit / Kai Aizen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> Note: the reproduced copyright line reflects the upstream repository's stated authorship at the time of
> adaptation. If the upstream notice differs, the upstream notice governs.
