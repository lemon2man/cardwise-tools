/**
 * APDU Response Debugger — ISO 7816-4 SW1 SW2 Status Word Decoder
 * @license MIT
 * @see https://cupass.com/en/tools/apdu-debugger.html
 *
 * Usage:
 *   import { decodeSW, decodeResponseHex } from './apdu-debugger/debugger.js';
 *   const result = decodeSW(0x69, 0x82);
 *   console.log(result); // { summary: 'Security status not satisfied', ... }
 */

/**
 * Complete ISO 7816-4 status word dictionary.
 * Maps SW1 class to categories and SW1-SW2 pairs to specific meanings.
 */
const SW_DICT = {
  // Normal processing
  '9000': { summary: 'Command completed successfully', severity: 'ok', category: 'Normal' },
  '61xx': { summary: 'Response data available — send GET RESPONSE (00 C0 00 00 SW2)', severity: 'ok', category: 'Normal (T=0)' },
  '6283': { summary: 'Selected file invalidated / locked', severity: 'warn', category: 'Warning' },

  // Verification / PIN warnings (63CX)
  '63Cx': { summary: 'PIN verification failed — X remaining attempt(s)', severity: 'warn', category: 'Warning (CHV)' },

  // Execution errors
  '6400': { summary: 'Execution error — state of non-volatile memory unchanged', severity: 'err', category: 'Execution Error' },
  '6500': { summary: 'Execution error — state of non-volatile memory changed', severity: 'err', category: 'Execution Error' },

  // Security errors
  '6600': { summary: 'Security-related error', severity: 'err', category: 'Security Error' },

  // Checking errors
  '6700': { summary: 'Wrong length (Lc/Le mismatch)', severity: 'err', fix: 'Check Lc value against expected command data length', category: 'Checking Error' },
  '6800': { summary: 'Functions in CLA not supported', severity: 'err', category: 'Checking Error' },
  '6982': { summary: 'Security status not satisfied — PIN not verified or access condition not met', severity: 'err', fix: 'Execute VERIFY command or select correct DF before retrying', category: 'Checking Error' },
  '6984': { summary: 'Referenced data invalidated / deactivated', severity: 'err', category: 'Checking Error' },
  '6985': { summary: 'Conditions of use not satisfied — wrong state for this command', severity: 'err', fix: 'Check command sequence; you may need to re-select DF or complete previous step', category: 'Checking Error' },
  '6986': { summary: 'Command not allowed (no current EF)', severity: 'err', fix: 'SELECT a file before this command', category: 'Checking Error' },

  '6A80': { summary: 'Incorrect data in command data field', severity: 'err', category: 'Checking Error' },
  '6A81': { summary: 'Function not supported', severity: 'err', category: 'Checking Error' },
  '6A82': { summary: 'File or application not found', severity: 'err', fix: 'Verify AID/FID exists under current DF; try partial AID selection', category: 'Checking Error' },
  '6A83': { summary: 'Record not found', severity: 'err', category: 'Checking Error' },
  '6A84': { summary: 'Not enough memory space in file', severity: 'err', category: 'Checking Error' },
  '6A86': { summary: 'Incorrect P1-P2', severity: 'err', fix: 'Verify P1/P2 values against command specification', category: 'Checking Error' },
  '6A88': { summary: 'Referenced data (key/PIN) not found', severity: 'err', fix: 'Check key reference or PIN ID', category: 'Checking Error' },

  '6B00': { summary: 'Wrong Le (expected length)', severity: 'err', category: 'Checking Error' },
  '6Cxx': { summary: 'Wrong Le — correct Le is SW2', severity: 'err', fix: 'Retry command with Le = SW2', category: 'Checking Error' },
  '6D00': { summary: 'Instruction code (INS) not supported', severity: 'err', fix: 'Check card documentation for supported INS values', category: 'Checking Error' },
  '6E00': { summary: 'Class (CLA) not supported', severity: 'err', fix: 'Check card documentation for supported CLA values', category: 'Checking Error' },
  '6F00': { summary: 'No precise diagnosis — unspecified error', severity: 'err', fix: 'Check command parameters; verify card state with SELECT first', category: 'Checking Error' },

  // Application-specific
  '6881': { summary: 'Logical channel not supported', severity: 'err', category: 'Application Error' },
  '6882': { summary: 'Secure messaging not supported', severity: 'err', category: 'Application Error' },
};

function swKey(sw1, sw2) {
  if (sw1 === 0x61) return '61xx';
  if (sw1 === 0x6C) return '6Cxx';
  if (sw1 === 0x63) return '63Cx';
  return [sw1, sw2].map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

/**
 * Decode a single SW1 SW2 status word pair.
 * @param {number} sw1 — SW1 byte (0-255)
 * @param {number} sw2 — SW2 byte (0-255)
 * @returns {{sw1:number, sw2:number, hex:string, summary:string, severity:string, category:string, fix:string|null, sw2Detail:string|null}}
 */
export function decodeSW(sw1, sw2) {
  const key = swKey(sw1, sw2);
  const entry = SW_DICT[key];

  const base = {
    sw1, sw2,
    hex: key,
    severity: entry ? entry.severity : 'err',
    summary: entry ? entry.summary : `Unknown status word (${key})`,
    category: entry ? entry.category : 'Unknown',
  };

  // SW2 detail for specific SW1 classes
  if (sw1 === 0x61) {
    base.sw2Detail = `${sw2} bytes available via GET RESPONSE (00 C0 00 00 ${sw2.toString(16).padStart(2,'0')})`;
    base.category = 'Normal (T=0)';
  } else if (sw1 === 0x6C) {
    base.sw2Detail = `Retry command with Le = 0x${sw2.toString(16).padStart(2,'0')} (${sw2})`;
  } else if (sw1 === 0x63) {
    base.sw2Detail = sw2 === 0 ? 'No more attempts remaining (CHV blocked)' : `${sw2 & 0x0F} attempt(s) remaining`;
  }

  return base;
}

/**
 * Decode a full APDU response (data + SW1 SW2).
 * Extracts SW1/SW2 from the last two bytes.
 * @param {number[]} response — full APDU response bytes or hex string
 * @returns decoded status word + data portion
 */
export function decodeResponse(response) {
  let bytes;
  if (typeof response === 'string') {
    const hex = response.replace(/\s/g, '');
    bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substring(i, i+2), 16));
  } else {
    bytes = response;
  }

  if (bytes.length < 2) throw new Error('Response must be at least 2 bytes (SW1 SW2)');

  const sw2 = bytes.pop();
  const sw1 = bytes.pop();

  return {
    data: new Uint8Array(bytes),
    dataHex: bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
    ...decodeSW(sw1, sw2)
  };
}
