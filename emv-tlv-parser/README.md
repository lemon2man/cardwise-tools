# EMV TLV Parser — BER-TLV Decoder with EMV Tag Registry

Parse EMV / ISO 7816-4 BER-TLV encoded data. Handles 1-byte and 2-byte tags, short/long form length encoding, constructed vs primitive tag detection. Includes a comprehensive registry of 80+ EMV tag names.

## Usage

```js
import { parseBER_TLV, parseBER_TLVHex, parseAFL } from './parser.js';

// Parse from hex
const tags = parseBER_TLVHex('5A 08 54 13 12 34 56 78 90 00 5F 24 03 25 12 31');

for (const t of tags) {
  console.log(t.tag);    // '5A'
  console.log(t.name);   // 'Application Primary Account Number (PAN)'
  console.log(t.hex);    // '54 13 12 34 56 78 90 00'
  console.log(t.length); // 8
}

// Parse AFL to get record read instructions
const afl = parseAFL([0x08, 0x01, 0x01, 0x00, 0x10, 0x03, 0x04, 0x01]);
// → [{ sfi: 1, first: 1, last: 1, odaRecords: 0 }, ...]
```

## Tag Registry

The parser includes `EMV_TAGS` — a registry of 80+ standard EMV tags mapping hex tag numbers to human-readable names and formats. Access it directly:

```js
import { EMV_TAGS } from './parser.js';
console.log(EMV_TAGS['9F36']); // { name: 'Application Transaction Counter (ATC)', format: 'b', len: '2' }
```

## BER-TLV Encoding Summary

| Tag Byte | Bit 7-6 | Bit 5 | Bits 4-0 |
|----------|---------|-------|----------|
| Meaning | Tag class | Constructed/primitive | Tag number |

- Bits 4-0 = `11111` → 2-byte tag
- Length byte bit 7 = 0 → short form (0-127)
- Length byte bit 7 = 1 → long form (bits 6-0 = subsequent bytes)
- Constructed tags (bit 5 = 1) contain nested TLV data

## Try Online

Use the interactive version at [cupass.com/en/tools/emv-tlv-parser.html](https://cupass.com/en/tools/emv-tlv-parser.html) — paste raw EMV hex and get instant tag-by-tag breakdown with value interpretation.

## Related Tools

- [CVM List Decoder](https://cupass.com/en/tools/cvm-list-decoder.html) — Decode EMV Cardholder Verification Methods
- [EMV Cryptogram Visualizer](https://cupass.com/en/tools/emv-cryptogram.html) — Step-by-step ARQC/ARPC generation
- [EMV Tag Reference](https://cupass.com/en/learn/emv-tags.html) — Complete EMV tag knowledge base

## License

MIT
