# ATR Decoder — ISO 7816-3 Answer to Reset Parser

Parse smart card ATR (Answer to Reset) byte sequences. Decodes TS initial character, T0 format byte, all interface bytes (TAi/TBi/TCi/TDi), detects T=0/T=1 protocol, extracts baud rate and historical bytes.

## Usage

```js
import { decodeATR, decodeATRHex } from './decoder.js';

// From hex string
const result = decodeATRHex('3B 9F 96 80 1F C7 80 31 E0 73 FE 21 1B 66 D0 01 7B 05 00 00 BA');

console.log(result.convention);      // 'direct'
console.log(result.protocols);       // ['T=0 (asynchronous half-duplex character transmission)']
console.log(result.baudRate);        // 115200
console.log(result.historicalBytes); // [0x31, 0xE0, 0x73, ...]

// From byte array
const result2 = decodeATR([0x3B, 0xDF, 0x18, 0x00, 0x81, 0x31, ...]);
```

## Return Value

| Field | Type | Description |
|-------|------|-------------|
| `ts` | number | TS initial character (0x3B = direct, 0x3F = inverse) |
| `convention` | string | `'direct'`, `'inverse'`, or `'non-standard'` |
| `t0` | number | T0 format byte |
| `histLen` | number | Number of historical bytes declared in T0 |
| `interfaceBytes` | array | TAi/TBi/TCi/TDi with per-byte decode info |
| `protocols` | string[] | Detected transport protocols |
| `baudRate` | number\|null | Calculated baud rate (if TA1 present) |
| `historicalBytes` | number[] | Up to 15 historical bytes from ATR |

## Try Online

Use the interactive version at [cupass.com/en/tools/atr-decoder.html](https://cupass.com/en/tools/atr-decoder.html) — paste ATR hex and get instant visual breakdown.

## Related Tools

- [APDU Response Debugger](../apdu-debugger/) — Decode SW1 SW2 status words
- [ISO 7816 Complete Guide](https://cupass.com/en/learn/iso7816-guide.html)

## License

MIT
