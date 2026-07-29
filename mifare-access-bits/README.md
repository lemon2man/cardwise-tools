# MIFARE Classic Access Bits Calculator

Encode and decode MIFARE Classic 1K/4K sector trailer access bits (bytes 6-9). Convert between human-readable C1/C2/C3 permissions and the raw hex bytes.

## Usage

```js
import { encodeAccessBits, decodeAccessBits, transportConfig } from './calculator.js';

// Decode transport configuration (FF 07 80)
const config = transportConfig();
console.log(config.valid);          // true
console.log(config.dataBlocks[0]);  // { block: 0, key: '000', read: 'Key A|B', write: 'Key A|B', ... }

// Encode custom permissions
const bytes = encodeAccessBits({
  dataBlocks: ['000', '000', '000'],  // Transport for data blocks
  trailer: '001'                       // Key A only for trailer
});
console.log(bytes); // { byte6: 0xFF, byte7: 0x07, byte8: 0x80, byte9: 0x69 }

// Decode arbitrary access bytes
const result = decodeAccessBits(0x08, 0x77, 0x8F);
console.log(result.dataBlocks[0].label); // 'Value Block'
```

## Access Bits Encoding

Each sector's trailer block contains 3 access bytes that encode C1/C2/C3 for all 4 blocks:

```
Byte 6: ~C2[3:0] ~C1[3:0]
Byte 7:  C1[3:0] ~C3[3:0]
Byte 8:  C3[3:0]  C2[3:0]
```

Both normal and inverted bits are stored — a mismatch permanently locks the sector.

## Try Online

Use the interactive version at [cupass.com/en/tools/mifare-access-bits.html](https://cupass.com/en/tools/mifare-access-bits.html) — toggle C1/C2/C3 per block and see bytes 6-9 update in real time.

## Related

- [NFC Capacity Calculator](https://cupass.com/en/tools/nfc-capacity.html) — Check NDEF capacity by chip type
- [MIFARE Classic vs DESFire Comparison](https://cupass.com/en/compare/mifare-comparison.html)

## License

MIT
