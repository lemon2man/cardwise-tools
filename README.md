# CardWise Tools — Smart Card Engineering Libraries

[CardWise](https://cupass.com/en/) is a free online toolbox for smart card engineers. This repository contains the standalone JavaScript engines that power the interactive tools — extracted so you can use them in your own projects.

**Every tool runs in-browser with zero dependencies.** Try the interactive versions at [cupass.com/en/tools/](https://cupass.com/en/tools/).

## Tools

| Tool | Directory | Try Online |
|------|-----------|------------|
| ATR Decoder | [`atr-decoder/`](atr-decoder/) | [cupass.com/en/tools/atr-decoder.html](https://cupass.com/en/tools/atr-decoder.html) |
| APDU Response Debugger | [`apdu-debugger/`](apdu-debugger/) | [cupass.com/en/tools/apdu-debugger.html](https://cupass.com/en/tools/apdu-debugger.html) |
| MIFARE Access Bits Calculator | [`mifare-access-bits/`](mifare-access-bits/) | [cupass.com/en/tools/mifare-access-bits.html](https://cupass.com/en/tools/mifare-access-bits.html) |
| NDEF Message Parser | [`ndef-parser/`](ndef-parser/) | [cupass.com/en/tools/ndef-parser.html](https://cupass.com/en/tools/ndef-parser.html) |
| EMV TLV Parser | [`emv-tlv-parser/`](emv-tlv-parser/) | [cupass.com/en/tools/emv-tlv-parser.html](https://cupass.com/en/tools/emv-tlv-parser.html) |

## Usage

Each tool is a single `.js` file. Copy it into your project and call its functions directly — no install, no build step.

```js
// Example: Decode an ATR
import { decodeATR } from './atr-decoder/decoder.js';

const result = decodeATR([0x3B, 0x9F, 0x96, 0x80, 0x1F, 0xC7, 0x80, 0x31, ...]);
console.log(result.protocols); // ['T=0']
console.log(result.historicalBytes); // [0x31, 0xE0, ...]
```

## Why Open Source

We believe smart card engineering tools should be transparent, auditable, and reusable. The interactive website handles UI/UX — this repo handles the pure computation logic. Use it in your CI pipeline, embed it in your card issuing system, or contribute improvements.

## License

MIT — see individual tool directories.

## Related

- [CardWise Knowledge Base](https://cupass.com/en/learn/) — ISO 7816, GlobalPlatform, EMV, NFC guides
- [CardWise Compare](https://cupass.com/en/compare/) — MIFARE Classic vs DESFire, T=0 vs T=1, eSIM vs SIM
