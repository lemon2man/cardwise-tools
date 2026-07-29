/**
 * EMV TLV Parser — BER-TLV (Tag-Length-Value) Decoder
 * @license MIT
 * @see https://cupass.com/en/tools/emv-tlv-parser.html
 *
 * Parse EMV/ISO 7816-4 BER-TLV encoded data. Handles 1-byte and 2-byte tags,
 * short/long form length encoding, constructed vs primitive tags,
 * and includes a comprehensive EMV tag name registry.
 *
 * Usage:
 *   import { parseBER_TLV, parseBER_TLVHex, EMV_TAGS } from './emv-tlv-parser/parser.js';
 */

/** Comprehensive EMV tag registry — maps tag hex to name, format, and class */
export const EMV_TAGS = {
  // Card / Application Data
  '42':  { name: 'Issuer Identification Number (IIN)', format: 'n', len: 'var' },
  '4F':  { name: 'Application Identifier (AID)', format: 'b', len: '5-16' },
  '50':  { name: 'Application Label', format: 'ans', len: '1-16' },
  '57':  { name: 'Track 2 Equivalent Data', format: 'b', len: 'var' },
  '5A':  { name: 'Application Primary Account Number (PAN)', format: 'n', len: 'var', maxLen: 10 },
  '5F20':{ name: 'Cardholder Name', format: 'ans', len: '2-26' },
  '5F24':{ name: 'Application Expiration Date (YYMMDD)', format: 'n', len: '3' },
  '5F25':{ name: 'Application Effective Date (YYMMDD)', format: 'n', len: '3' },
  '5F28':{ name: 'Issuer Country Code', format: 'n', len: '2' },
  '5F2A':{ name: 'Transaction Currency Code', format: 'n', len: '2' },
  '5F2D':{ name: 'Language Preference', format: 'ans', len: '2-8' },
  '5F30':{ name: 'Service Code', format: 'n', len: '1-3' },
  '5F34':{ name: 'Application PAN Sequence Number', format: 'n', len: '1' },
  '5F36':{ name: 'Transaction Currency Exponent', format: 'n', len: '1' },
  '5F50':{ name: 'Issuer URL', format: 'ans', len: 'var' },
  '5F53':{ name: 'International Bank Account Number (IBAN)', format: 'b', len: 'var' },
  '5F54':{ name: 'Bank Identifier Code (BIC)', format: 'b', len: 'var' },
  '5F55':{ name: 'Issuer Country Code (Alpha2)', format: 'ans', len: '2' },
  '5F56':{ name: 'Issuer Country Code (Alpha3)', format: 'ans', len: '3' },

  // Application Usage / Risk
  '82':  { name: 'Application Interchange Profile (AIP)', format: 'b', len: '2' },
  '84':  { name: 'Dedicated File (DF) Name', format: 'b', len: '5-16' },
  '87':  { name: 'Application Priority Indicator', format: 'b', len: '1' },
  '88':  { name: 'SFI of the Directory Elementary File', format: 'b', len: '1' },
  '8A':  { name: 'Authorised Response Code', format: 'b', len: '1' },
  '8C':  { name: 'Card Data Object List 1 (CDOL1)', format: 'b', len: 'var' },
  '8D':  { name: 'Card Data Object List 2 (CDOL2)', format: 'b', len: 'var' },
  '8E':  { name: 'CVM List', format: 'b', len: 'var' },
  '8F':  { name: 'Certification Authority Public Key Index', format: 'b', len: '1' },
  '90':  { name: 'Issuer Public Key Certificate', format: 'b', len: 'var' },
  '91':  { name: 'Issuer Authentication Data', format: 'b', len: 'var' },
  '92':  { name: 'Issuer Public Key Remainder', format: 'b', len: 'var' },
  '93':  { name: 'Signed Static Application Data', format: 'b', len: 'var' },
  '94':  { name: 'Application File Locator (AFL)', format: 'b', len: 'var' },
  '95':  { name: 'Terminal Verification Results (TVR)', format: 'b', len: '5' },
  '97':  { name: 'Transaction Certificate Data Object List (TDOL)', format: 'b', len: 'var' },
  '98':  { name: 'Transaction Certificate (TC) Hash Value', format: 'b', len: '20' },
  '99':  { name: 'Transaction PIN Data', format: 'b', len: 'var' },

  // Transaction Data
  '9A':  { name: 'Transaction Date (YYMMDD)', format: 'n', len: '3' },
  '9B':  { name: 'Transaction Status Information (TSI)', format: 'b', len: '2' },
  '9C':  { name: 'Transaction Type', format: 'n', len: '1' },
  '9F01':{ name: 'Acquirer Identifier', format: 'n', len: '6-11' },
  '9F02':{ name: 'Amount, Authorised (Numeric)', format: 'n', len: '6' },
  '9F03':{ name: 'Amount, Other (Numeric)', format: 'n', len: '6' },
  '9F06':{ name: 'Application Identifier (Terminal)', format: 'b', len: '5-16' },
  '9F07':{ name: 'Application Usage Control', format: 'b', len: '2' },
  '9F08':{ name: 'Application Version Number (ICC)', format: 'b', len: '2' },
  '9F0D':{ name: 'Issuer Action Code — Default', format: 'b', len: '5' },
  '9F0E':{ name: 'Issuer Action Code — Denial', format: 'b', len: '5' },
  '9F0F':{ name: 'Issuer Action Code — Online', format: 'b', len: '5' },
  '9F10':{ name: 'Issuer Application Data (IAD)', format: 'b', len: 'var' },
  '9F11':{ name: 'Issuer Code Table Index', format: 'n', len: '1' },
  '9F12':{ name: 'Application Preferred Name', format: 'ans', len: '1-16' },
  '9F13':{ name: 'Last Online ATC Register', format: 'b', len: '2' },
  '9F14':{ name: 'Lower Consecutive Offline Limit', format: 'b', len: 'var' },
  '9F15':{ name: 'Merchant Category Code', format: 'n', len: '2' },
  '9F16':{ name: 'Merchant Identifier', format: 'ans', len: '15' },
  '9F17':{ name: 'PIN Try Counter', format: 'b', len: '1' },
  '9F1A':{ name: 'Terminal Country Code', format: 'n', len: '2' },
  '9F1E':{ name: 'Interface Device (IFD) Serial Number', format: 'ans', len: '8' },
  '9F21':{ name: 'Transaction Time (HHMMSS)', format: 'n', len: '3' },
  '9F26':{ name: 'Application Cryptogram (AC)', format: 'b', len: '8' },
  '9F27':{ name: 'Cryptogram Information Data (CID)', format: 'b', len: '1' },
  '9F32':{ name: 'Issuer Public Key Exponent', format: 'b', len: '1-3' },
  '9F33':{ name: 'Terminal Capabilities', format: 'b', len: '3' },
  '9F34':{ name: 'CVM Results', format: 'b', len: '3' },
  '9F35':{ name: 'Terminal Type', format: 'n', len: '1' },
  '9F36':{ name: 'Application Transaction Counter (ATC)', format: 'b', len: '2' },
  '9F37':{ name: 'Unpredictable Number (UN)', format: 'b', len: '4' },
  '9F39':{ name: 'POS Entry Mode', format: 'n', len: '1' },
  '9F40':{ name: 'Additional Terminal Capabilities', format: 'b', len: '5' },
  '9F41':{ name: 'Transaction Sequence Counter', format: 'n', len: '2-4' },
  '9F42':{ name: 'Application Currency Code', format: 'n', len: '2' },
  '9F44':{ name: 'Application Currency Exponent', format: 'n', len: '1' },
  '9F45':{ name: 'Data Authentication Code', format: 'b', len: '2' },
  '9F46':{ name: 'ICC Public Key Certificate', format: 'b', len: 'var' },
  '9F47':{ name: 'ICC Public Key Exponent', format: 'b', len: '1-3' },
  '9F48':{ name: 'ICC Public Key Remainder', format: 'b', len: 'var' },
  '9F49':{ name: 'DDOL', format: 'b', len: 'var' },
  '9F4A':{ name: 'Static Data Authentication Tag List', format: 'b', len: 'var' },
  '9F53':{ name: 'Consecutive Transaction Limit (Intl)', format: 'b', len: 'var' },
  '9F5B':{ name: 'Issuer Script Results', format: 'b', len: 'var' },
  '9F66':{ name: 'Terminal Transaction Information (TTI)', format: 'b', len: '4' },

  // Templates
  '61':  { name: 'Application Template', format: 'b', len: 'var', constructed: true },
  '6F':  { name: 'FCI Template', format: 'b', len: 'var', constructed: true },
  '70':  { name: 'READ RECORD Response Template', format: 'b', len: 'var', constructed: true },
  '71':  { name: 'Issuer Script Template 1', format: 'b', len: 'var', constructed: true },
  '72':  { name: 'Issuer Script Template 2', format: 'b', len: 'var', constructed: true },
  '73':  { name: 'Directory Discretionary Template', format: 'b', len: 'var', constructed: true },
  '77':  { name: 'Response Message Template Format 2', format: 'b', len: 'var', constructed: true },
  '80':  { name: 'Response Message Template Format 1', format: 'b', len: 'var', constructed: true },
  'A5':  { name: 'FCI Proprietary Template', format: 'b', len: 'var', constructed: true },
  'BF0C':{ name: 'FCI Issuer Discretionary Data', format: 'b', len: 'var', constructed: true },
};

/**
 * Parse BER-TLV encoded data into structured tag objects.
 * @param {number[]|Uint8Array} bytes
 * @param {number} [offset=0]
 * @returns {object[]} — array of { tag, length, value, hex, name, format, constructed }
 */
export function parseBER_TLV(bytes, offset = 0) {
  if (bytes instanceof Uint8Array) bytes = Array.from(bytes);
  const tags = [];

  while (offset < bytes.length) {
    if (offset >= bytes.length) break;

    let tag = bytes[offset].toString(16).padStart(2, '0').toUpperCase();
    let isConstructed = !!(bytes[offset] & 0x20);
    offset++;

    // 2-byte tag (bit 5 of first byte = 1)
    if ((bytes[offset - 1] & 0x1F) === 0x1F) {
      if (offset < bytes.length) {
        tag += bytes[offset].toString(16).padStart(2, '0').toUpperCase();
        isConstructed = !!(bytes[offset] & 0x20);
        offset++;
      }
    }

    if (offset >= bytes.length) break;

    // Length encoding
    let len = bytes[offset];
    offset++;

    if (len === 0x81) { len = bytes[offset]; offset++; }
    else if (len === 0x82) { len = (bytes[offset]<<8)|bytes[offset+1]; offset+=2; }
    else if (len === 0x83) { len = (bytes[offset]<<16)|(bytes[offset+1]<<8)|bytes[offset+2]; offset+=3; }

    if (len > 0x7FFFFFFF || offset + len > bytes.length) break;

    const value = bytes.slice(offset, offset + len);
    offset += len;

    const tagInfo = EMV_TAGS[tag] || null;

    tags.push({
      tag,
      length: len,
      value: new Uint8Array(value),
      hex: value.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
      name: tagInfo ? tagInfo.name : null,
      format: tagInfo ? tagInfo.format : null,
      constructed: isConstructed,
    });
  }

  return tags;
}

/**
 * Convenience: parse from hex string.
 * @param {string} hex
 * @returns {object[]}
 */
export function parseBER_TLVHex(hex) {
  const clean = hex.replace(/\s/g, '');
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substring(i, i+2), 16));
  return parseBER_TLV(bytes);
}

/**
 * Parse AFL (Application File Locator) bytes into record read instructions.
 * @param {number[]} afl — tag 0x94 value bytes
 * @returns {{sfi:number, first:number, last:number, odaRecords:number}[]}
 */
export function parseAFL(afl) {
  const entries = [];
  for (let i = 0; i < afl.length; i += 4) {
    entries.push({
      sfi: afl[i] >> 3,
      first: afl[i + 1],
      last: afl[i + 2],
      odaRecords: afl[i + 3],
    });
  }
  return entries;
}
