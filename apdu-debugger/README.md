# APDU Response Debugger — SW1 SW2 Status Word Decoder

Decode ISO 7816-4 APDU response status words (SW1 SW2) to human-readable explanations. Covers all standard classes: normal processing (9000, 61XX), warnings (62XX, 63CX), and errors (64XX-6F00).

## Usage

```js
import { decodeSW, decodeResponse } from './debugger.js';

// Decode status word bytes
const result = decodeSW(0x69, 0x82);
console.log(result.summary);
// → 'Security status not satisfied — PIN not verified or access condition not met'
console.log(result.fix);
// → 'Execute VERIFY command or select correct DF before retrying'

// Decode full APDU response (extracts SW1 SW2 from last 2 bytes)
const resp = decodeResponse('1B 66 D0 01 7B 05 90 00');
console.log(resp.hex);      // '9000'
console.log(resp.severity); // 'ok'
console.log(resp.dataHex);  // '1B 66 D0 01 7B 05'
```

## Status Word Quick Reference

| SW1 SW2 | Category | Meaning |
|---------|----------|---------|
| 90 00 | Normal | Command completed successfully |
| 61 XX | Normal (T=0) | XX bytes available via GET RESPONSE |
| 63 CX | Warning | PIN failed — X attempts remaining |
| 67 00 | Error | Wrong length |
| 69 82 | Error | Security status not satisfied |
| 6A 82 | Error | File/application not found |
| 6A 86 | Error | Incorrect P1-P2 |
| 6D 00 | Error | INS not supported |
| 6E 00 | Error | CLA not supported |

## Try Online

Use the interactive version at [cupass.com/en/tools/apdu-debugger.html](https://cupass.com/en/tools/apdu-debugger.html) — paste any APDU response hex and get byte-by-byte breakdown.

## Related Tools

- [APDU Command Builder](https://cupass.com/en/tools/apdu-builder.html) — Construct APDU commands interactively
- [ATR Decoder](../atr-decoder/) — Parse smart card ATR bytes

## License

MIT
