/**
 * NDEF Message Parser — NFC Data Exchange Format decoder
 * @license MIT
 * @see https://cupass.com/en/tools/ndef-parser.html
 *
 * Parse raw NDEF message bytes into structured records.
 * Supports all TNF types: Well-Known (Text, URI, Smart Poster), MIME, External, etc.
 *
 * Usage:
 *   import { parseNDEFMessage, parseNDEFHex } from './ndef-parser/parser.js';
 */

/** URI abbreviation prefix table (NFC Forum RTD-URI) */
const URI_PREFIXES = {
  '0x00': '',
  '0x01': 'http://www.',
  '0x02': 'https://www.',
  '0x03': 'http://',
  '0x04': 'https://',
  '0x05': 'tel:',
  '0x06': 'mailto:',
  '0x07': 'ftp://anonymous:anonymous@',
  '0x08': 'ftp://ftp.',
  '0x09': 'ftps://',
  '0x0A': 'sftp://',
  '0x0B': 'smb://',
  '0x0C': 'nfs://',
  '0x0D': 'ftp://',
  '0x0E': 'dav://',
  '0x0F': 'news:',
  '0x10': 'telnet://',
  '0x11': 'imap:',
  '0x12': 'rtsp://',
  '0x13': 'urn:',
  '0x14': 'pop:',
  '0x15': 'sip:',
  '0x16': 'sips:',
  '0x17': 'tftp:',
  '0x18': 'btspp://',
  '0x19': 'btl2cap://',
  '0x1A': 'btgoep://',
  '0x1B': 'tcpobex://',
  '0x1C': 'irdaobex://',
  '0x1D': 'file://',
  '0x1E': 'urn:epc:id:',
  '0x1F': 'urn:epc:tag:',
  '0x20': 'urn:epc:pat:',
  '0x21': 'urn:epc:raw:',
  '0x22': 'urn:epc:',
  '0x23': 'urn:nfc:',
};

const TNF_NAMES = {
  0x00: 'Empty',
  0x01: 'Well-Known (NFC Forum RTD)',
  0x02: 'MIME (RFC 2046)',
  0x03: 'Absolute URI',
  0x04: 'External (NFC Forum RTD)',
  0x05: 'Unknown',
  0x06: 'Unchanged (chunked record)',
  0x07: 'Reserved',
};

/**
 * Parse a single NDEF record from bytes at given offset.
 * @param {number[]|Uint8Array} bytes
 * @param {number} offset
 * @returns {{mb, me, cf, sr, il, tnf, typeLen, payloadLen, idLen, type, id, payload, nextOffset}|null}
 */
function readNDEFRecord(bytes, offset) {
  if (offset >= bytes.length) return null;

  const flags = bytes[offset];
  const mb = (flags >> 7) & 1;
  const me = (flags >> 6) & 1;
  const cf = (flags >> 5) & 1;
  const sr = (flags >> 3) & 1;
  const il = (flags >> 2) & 1;
  const tnf = flags & 0x07;

  offset++;
  if (offset >= bytes.length) return null;
  const typeLen = bytes[offset++];

  let payloadLen;
  if (sr) {
    if (offset >= bytes.length) return null;
    payloadLen = bytes[offset++];
  } else {
    if (offset + 3 >= bytes.length) return null;
    payloadLen = (bytes[offset]<<24)|(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3];
    offset += 4;
  }

  let idLen = 0;
  if (il) {
    if (offset >= bytes.length) return null;
    idLen = bytes[offset++];
  }

  if (offset + typeLen + idLen + payloadLen > bytes.length) return null;

  const type = bytes.slice(offset, offset + typeLen);
  offset += typeLen;
  const id = bytes.slice(offset, offset + idLen);
  offset += idLen;
  const payload = bytes.slice(offset, offset + payloadLen);
  offset += payloadLen;

  return { mb, me, cf, sr, il, tnf, typeLen, payloadLen, idLen, type, id, payload, nextOffset: offset };
}

/**
 * Decode a Well-Known Text record payload.
 * @param {Uint8Array} payload
 * @returns {{lang:string, text:string, utf16:boolean}}
 */
export function decodeTextPayload(payload) {
  if (payload.length < 2) return { lang: '', text: '', utf16: false };
  const status = payload[0];
  const utf16 = !!(status & 0x80);
  const langLen = status & 0x3F;
  const lang = String.fromCharCode(...payload.slice(1, 1 + langLen));
  const data = payload.slice(1 + langLen);
  const decoder = new TextDecoder(utf16 ? 'utf-16be' : 'utf-8');
  return { lang, text: decoder.decode(data), utf16 };
}

/**
 * Decode a Well-Known URI record payload.
 * @param {Uint8Array} payload
 * @returns {string}
 */
export function decodeUriPayload(payload) {
  if (payload.length < 1) return '';
  const prefixCode = `0x${payload[0].toString(16).padStart(2, '0').toUpperCase()}`;
  const prefix = URI_PREFIXES[prefixCode] || '';
  const decoder = new TextDecoder();
  return prefix + decoder.decode(payload.slice(1));
}

/**
 * Decode a Smart Poster record payload (nested NDEF message).
 * @param {Uint8Array} payload
 * @returns {{uri:string, titles:string[]}}
 */
export function decodeSmartPosterPayload(payload) {
  const nested = parseNDEFMessage(Array.from(payload));
  const result = { uri: '', titles: [] };
  for (const r of nested) {
    if (r.tnf === 0x01) {
      const wkt = r.type[0];
      if (wkt === 0x55) result.uri = decodeUriPayload(r.payload); // URI
      if (wkt === 0x54) { // Text
        const t = decodeTextPayload(r.payload);
        result.titles.push(`${t.text} (${t.lang})`);
      }
    }
  }
  return result;
}

/**
 * Parse a complete NDEF message from raw bytes.
 * @param {number[]|Uint8Array} bytes
 * @returns {object[]} — array of parsed record objects
 */
export function parseNDEFMessage(bytes) {
  if (bytes instanceof Uint8Array) bytes = Array.from(bytes);
  const records = [];
  let offset = 0;
  while (offset < bytes.length) {
    const rec = readNDEFRecord(bytes, offset);
    if (!rec) break;
    rec.tnfName = TNF_NAMES[rec.tnf] || 'Unknown';

    // Decode well-known record payloads
    if (rec.tnf === 0x01 && rec.type.length === 1) {
      const wkt = rec.type[0];
      if (wkt === 0x54) rec.decoded = decodeTextPayload(rec.payload);
      else if (wkt === 0x55) rec.decoded = { uri: decodeUriPayload(rec.payload) };
      else if (wkt === 0x53) rec.decoded = decodeSmartPosterPayload(rec.payload);
    }

    // Decode MIME record
    if (rec.tnf === 0x02) {
      rec.mimeType = String.fromCharCode(...rec.type);
    }

    records.push(rec);
    if (rec.me) break;
  }
  return records;
}

/**
 * Convenience: parse NDEF from hex string.
 * @param {string} hex
 * @returns {object[]}
 */
export function parseNDEFHex(hex) {
  const clean = hex.replace(/\s/g, '');
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substring(i, i+2), 16));
  return parseNDEFMessage(bytes);
}
