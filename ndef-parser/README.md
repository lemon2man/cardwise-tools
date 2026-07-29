# NDEF Message Parser — NFC Data Exchange Format Decoder

Parse raw NDEF (NFC Data Exchange Format) messages from byte arrays or hex. Decodes all record types: Well-Known Text, URI, Smart Poster, MIME, Absolute URI, External. Handles chunked records and multi-record messages.

## Usage

```js
import { parseNDEFMessage, parseNDEFHex, decodeTextPayload, decodeUriPayload } from './parser.js';

// Parse from hex
const records = parseNDEFHex('D1 01 04 54 02 65 6E 48 69');

// Parse from bytes
const records2 = parseNDEFMessage([0xD1, 0x01, 0x04, 0x54, 0x02, 0x65, 0x6E, 0x48, 0x69]);

// Each record object:
// { mb, me, cf, sr, il, tnf, tnfName, type, payload, decoded, ... }

for (const r of records) {
  console.log(r.tnfName);         // 'Well-Known (NFC Forum RTD)'
  console.log(r.type[0] === 0x54); // true (Text record)
  console.log(r.decoded);          // { lang: 'en', text: 'Hi', utf16: false }
}
```

## Record Types Supported

| TNF | Type | Description | `decoded` field |
|-----|------|-------------|-----------------|
| 0x01 | `T` (0x54) | Well-Known Text | `{ lang, text, utf16 }` |
| 0x01 | `U` (0x55) | Well-Known URI | `{ uri }` |
| 0x01 | `Sp` (0x53) | Smart Poster | `{ uri, titles[] }` |
| 0x02 | MIME | MIME type | `mimeType` + raw payload |
| 0x03 | Absolute URI | Full URI reference | Raw payload |
| 0x04 | External | Vendor-specific | Raw payload |

## Low-Level Functions

```js
import { decodeTextPayload, decodeUriPayload, decodeSmartPosterPayload } from './parser.js';

// Decode individual record payloads
decodeTextPayload(payload);       // { lang, text, utf16 }
decodeUriPayload(payload);        // "https://cupass.com"
decodeSmartPosterPayload(payload); // { uri: "...", titles: [...] }
```

## Try Online

Use the interactive version at [cupass.com/en/tools/ndef-parser.html](https://cupass.com/en/tools/ndef-parser.html) — paste NDEF hex and see all records decoded with full structure visualization.

## Related Tools

- [NDEF Writer Simulator](https://cupass.com/en/tools/ndef-writer.html) — Build NDEF messages interactively
- [NFC Capacity Calculator](https://cupass.com/en/tools/nfc-capacity.html) — Check if your NDEF fits on a tag

## License

MIT
