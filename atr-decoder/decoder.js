/**
 * ATR Decoder — ISO 7816-3 Answer to Reset Parser
 * @license MIT
 * @see https://cupass.com/en/tools/atr-decoder.html
 *
 * Usage:
 *   import { decodeATR } from './atr-decoder/decoder.js';
 *   const result = decodeATR([0x3B, 0x9F, 0x96, 0x80, ...]);
 *   console.log(result.protocols); // ['T=0', 'T=1']
 */

const PROTOCOL_NAMES = {
  0:  'T=0 (asynchronous half-duplex character transmission)',
  1:  'T=1 (asynchronous half-duplex block transmission)',
  2:  'T=2 (reserved)',
  3:  'T=3 (reserved)',
  14: 'T=14 (reserved, some vendors use)'
};

const FI_TABLE = {
  0:372, 1:372, 2:558, 3:744, 4:1116, 5:1488, 6:1860,
  7:'RFU', 8:'RFU', 9:512, 10:768, 11:1024, 12:1536,
  13:2048, 14:'RFU', 15:'RFU'
};

const DI_TABLE = {
  0:'RFU', 1:1, 2:2, 3:4, 4:8, 5:16, 6:32, 7:64,
  8:12, 9:20, 10:'RFU', 11:'RFU', 12:'RFU', 13:'RFU',
  14:'RFU', 15:'RFU'
};

const CLK_FREQ = 3571200; // Hz

/**
 * Decode an ISO 7816-3 ATR byte sequence.
 * @param {number[]} bytes — raw ATR bytes
 * @returns {{ts, t0, protocols: string[], interfaceBytes: object[], historicalBytes: number[], baudRate: number|null}}
 */
export function decodeATR(bytes) {
  if (bytes.length < 2) throw new Error('ATR requires at least 2 bytes (TS + T0)');

  let idx = 0;

  // TS — Initial Character
  const ts = bytes[idx++];
  const convention = (ts === 0x3B) ? 'direct' : (ts === 0x3F) ? 'inverse' : 'non-standard';

  // T0 — Format Byte
  const t0 = bytes[idx++];
  const histLen = t0 & 0x0F;
  let hasTA = !!(t0 & 0x10);
  let hasTB = !!(t0 & 0x20);
  let hasTC = !!(t0 & 0x40);
  let hasTD = !!(t0 & 0x80);

  // Interface bytes loop
  const protocols = [];
  const interfaceBytes = [];
  let tdIdx = 1;
  let baudRate = null;

  while (hasTD) {
    if (hasTA && idx < bytes.length) {
      const val = bytes[idx++];
      const entry = { type: `TA${tdIdx}`, value: val };
      if (tdIdx === 1) {
        const fi = (val >> 4) & 0x0F;
        const di = val & 0x0F;
        const F = FI_TABLE[fi], D = DI_TABLE[di];
        if (typeof F === 'number' && typeof D === 'number') {
          baudRate = Math.round(CLK_FREQ * D / F);
          entry.decode = { fi, di, F, D, baudRate };
        }
      } else if (tdIdx === 2) {
        entry.decode = {
          negotiable: !!(val & 0x80),
          protocol: PROTOCOL_NAMES[val & 0x0F] || `T=${val & 0x0F}`
        };
      }
      interfaceBytes.push(entry);
      hasTA = false;
    }
    if (hasTB && idx < bytes.length) {
      const val = bytes[idx++];
      const entry = { type: `TB${tdIdx}`, value: val };
      if (tdIdx === 1) {
        entry.decode = {
          iMax: (val >> 4) & 0x0F,
          iMin: val & 0x0F,
          vppRequired: !!(val & 0x80),
          programmingCurrent: !!(val & 0x40)
        };
      }
      interfaceBytes.push(entry);
      hasTB = false;
    }
    if (hasTC && idx < bytes.length) {
      const val = bytes[idx++];
      const entry = { type: `TC${tdIdx}`, value: val };
      if (tdIdx === 1) entry.decode = { extraGuardTime: val };
      interfaceBytes.push(entry);
      hasTC = false;
    }
    if (idx >= bytes.length) break;

    const td = bytes[idx++];
    const proto = td & 0x0F;
    if (proto <= 14) protocols.push(PROTOCOL_NAMES[proto] || `T=${proto}`);

    interfaceBytes.push({
      type: `TD${tdIdx}`,
      value: td,
      decode: {
        protocol: PROTOCOL_NAMES[proto] || `T=${proto}`,
        hasTA_next: !!(td & 0x10),
        hasTB_next: !!(td & 0x20),
        hasTC_next: !!(td & 0x40),
        hasTD_next: !!(td & 0x80)
      }
    });

    hasTA = !!(td & 0x10);
    hasTB = !!(td & 0x20);
    hasTC = !!(td & 0x40);
    hasTD = !!(td & 0x80);
    tdIdx++;
  }

  if (protocols.length === 0) protocols.push(PROTOCOL_NAMES[0]);

  // Historical bytes
  const historicalBytes = [];
  while (idx < bytes.length && historicalBytes.length < 15) {
    historicalBytes.push(bytes[idx++]);
  }

  return { ts, convention, t0, histLen, interfaceBytes, protocols, baudRate, historicalBytes };
}

/**
 * Convenience: decode from hex string.
 * @param {string} hex — hex ATR string like "3B 9F 96 80..."
 * @returns decoded result (same as decodeATR)
 */
export function decodeATRHex(hex) {
  const clean = hex.replace(/\s/g, '').replace(/[^0-9A-Fa-f]/g, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex length');
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substring(i, i+2), 16));
  return decodeATR(bytes);
}
