/**
 * MIFARE Classic Access Bits Calculator
 * @license MIT
 * @see https://cupass.com/en/tools/mifare-access-bits.html
 *
 * Encode C1/C2/C3 permissions into sector trailer bytes 6-9.
 * Decode existing access bytes back to per-block permissions.
 *
 * Usage:
 *   import { encodeAccessBits, decodeAccessBits } from './mifare-access-bits/calculator.js';
 */

/** C1/C2/C3 → access permissions mapping for data blocks */
const DATA_BLOCK_PERMS = {
  '000': { read: 'Key A|B', write: 'Key A|B', increment: 'Key A|B', decrTransRest: 'Key A|B', label: 'Transport (open)' },
  '010': { read: 'Key A|B', write: 'Never',   increment: 'Never',    decrTransRest: 'Never',    label: 'Read-only' },
  '100': { read: 'Key A|B', write: 'Key B',   increment: 'Never',    decrTransRest: 'Never',    label: 'Read Key A|B, Write Key B' },
  '110': { read: 'Key A|B', write: 'Key B',   increment: 'Key A|B',  decrTransRest: 'Key A|B',  label: 'Value Block' },
  '001': { read: 'Key A|B', write: 'Never',   increment: 'Never',    decrTransRest: 'Key A|B',  label: 'Transport (read)' },
  '011': { read: 'Key B',   write: 'Key B',   increment: 'Never',    decrTransRest: 'Never',    label: 'Protected (Key B)' },
  '101': { read: 'Key B',   write: 'Never',   increment: 'Never',    decrTransRest: 'Never',    label: 'Private (Key B read only)' },
  '111': { read: 'Never',   write: 'Never',   increment: 'Never',    decrTransRest: 'Never',    label: 'Blocked' },
};

/** Sector trailer access conditions for Key A / Access Bits / Key B */
const TRAILER_ACCS = [
  { label: '(000) Transport — Key A wr, Key B r/wr with Key A',     keyA: 'read never, write Key A', accBits: 'r/w Key A',          keyB: 'r/w Key A (Key B is data)' },
  { label: '(001) Key A wr only, Key B locked',                     keyA: 'read never, write never',  accBits: 'read Key A, write never',  keyB: 'read never, write Key A' },
  { label: '(010) Read-only, Key B locked to data',                 keyA: 'read never, write Key A', accBits: 'read Key A, write Key A', keyB: 'read Key A (Key B is data)' },
  { label: '(011) Key B wr only, Key A locked',                     keyA: 'read never, write never',  accBits: 'read Key A|B, write Key B', keyB: 'read never, write Key B' },
  { label: '(100) All locked',                                      keyA: 'read never, write never',  accBits: 'read Key A|B, write never', keyB: 'read never, write never' },
  { label: '(101) Key B wr only, access bits readable',             keyA: 'read never, write never',  accBits: 'read Key A|B, write Key B', keyB: 'read never, write Key B' },
  { label: '(110) Key B wr only, Key A locked',                     keyA: 'read never, write Key B', accBits: 'read Key A|B, write Key B', keyB: 'read never, write never' },
  { label: '(111) All locked',                                      keyA: 'read never, write never',  accBits: 'read Key A|B, write never', keyB: 'read never, write never' },
];

/**
 * Create a C1/C2/C3 triplet array from individual bits.
 * @param {number|string} c1
 * @param {number|string} c2
 * @param {number|string} c3
 * @returns {string} — e.g., '010' for C1=0, C2=1, C3=0
 */
function triplet(c1, c2, c3) { return `${Number(c1)}${Number(c2)}${Number(c3)}`; }

/**
 * Pack access bits into sector trailer bytes 6-9.
 * @param {object} perms — { dataBlocks: [3×string C1C2C3], trailer: string C1C2C3 }
 * @returns {{byte6:number, byte7:number, byte8:number, byte9:number}}
 */
export function encodeAccessBits(perms) {
  const data = perms.dataBlocks.map(b => parseInt(b, 2));
  const tr = parseInt(perms.trailer, 2);

  const c1 = [data[0]>>2, data[1]>>2, data[2]>>2, tr>>2];
  const c2 = [(data[0]>>1)&1, (data[1]>>1)&1, (data[2]>>1)&1, (tr>>1)&1];
  const c3 = [data[0]&1, data[1]&1, data[2]&1, tr&1];

  const pack4 = bits => (bits[3]<<3)|(bits[2]<<2)|(bits[1]<<1)|bits[0];
  const inv4 = bits => ~pack4(bits) & 0x0F;

  const byte6 = (inv4(c2)<<4) | inv4(c1);
  const byte7 = (pack4(c1)<<4) | inv4(c3);
  const byte8 = (pack4(c3)<<4) | pack4(c2);

  return { byte6, byte7, byte8, byte9: 0x69 };
}

/**
 * Decode sector trailer access bytes to per-block permissions.
 * @param {number} byte6, byte7, byte8 — access bytes from trailer
 * @returns {{ dataBlocks: object[], trailer: object }}
 */
export function decodeAccessBits(byte6, byte7, byte8) {
  // Extract C1/C2/C3 bits per block (blocks 0,1,2 for data, 3 for trailer)
  const find = (b6, b7, b8) => {
    // byte6: ~C2[3:0] ~C1[3:0]
    // byte7:  C1[3:0] ~C3[3:0]
    // byte8:  C3[3:0]  C2[3:0]
    const c1 = [(b7>>4)&1, (b7>>5)&1, (b7>>6)&1, (b7>>7)&1];
    const c2 = [b8&1, (b8>>1)&1, (b8>>2)&1, (b8>>3)&1];
    const c3 = [(~b7)&1, ((~b7)>>1)&1, ((~b7)>>2)&1, ((~b7)>>3)&1];
    // Validate inverted bits in byte6
    const _c1 = [(~b6)&1, ((~b6)>>1)&1, ((~b6)>>2)&1, ((~b6)>>3)&1];
    const _c2 = [(~(b6>>4))&1, (~(b6>>5))&1, (~(b6>>6))&1, (~(b6>>7))&1];
    const valid = c1.every((v,i) => v === _c1[i]) && c2.every((v,i) => v === _c2[i]);
    return { c1, c2, c3, valid };
  };

  const bits = find(byte6, byte7, byte8);
  const dataBlocks = [0,1,2].map(i => {
    const key = triplet(bits.c1[i], bits.c2[i], bits.c3[i]);
    return { block: i, key, ...(DATA_BLOCK_PERMS[key] || { label: 'Invalid' }), valid: bits.valid };
  });

  const trKey = triplet(bits.c1[3], bits.c2[3], bits.c3[3]);
  const trailerIdx = parseInt(trKey, 2);
  const trailer = { block: 3, key: trKey, ...(TRAILER_ACCS[trailerIdx] || { label: 'Unknown' }), valid: bits.valid };

  return { dataBlocks, trailer, valid: bits.valid, bytes: { byte6, byte7, byte8 } };
}

/**
 * Convenience: parse transport configuration (FF 07 80).
 * @returns decoded transport configuration
 */
export function transportConfig() {
  return decodeAccessBits(0xFF, 0x07, 0x80);
}
