'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const utf8 = require('utf8');
var base64js = require('base64-js');

const Buffer = require('buffer').Buffer;
const RNSimpleCrypto = require('@react-native-cryptocurrencies/react-native-simple-crypto')
  .default;
const pbkdf2_1 = require('@react-native-cryptocurrencies/react-native-pbkdf2')
  .default;
const sha = RNSimpleCrypto.SHA;

const randomBytes = require('react-native-securerandom').generateSecureRandom;
const _wordlists_1 = require('./_wordlists');

let DEFAULT_WORDLIST = _wordlists_1._default;
const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED =
  'A wordlist is required but a default could not be found.\n' +
  'Please explicitly pass a 2048 word array explicitly.';

function pbkdf2Promise(password, saltMixin, iterations, keylen, digest) {
  /*
  console.log('[BIP39] run PBKDF2 with: ', {
    password,
    password_str: password.toString(),
    password_hex: password.toString('hex'),
    saltMixin,
    salt_str: saltMixin.toString(),
    salt_hex: saltMixin.toString('hex'),
    iterations,
  });
  */
  return pbkdf2_1.derivationKey(
    password.toString(),
    saltMixin.toString(),
    iterations,
  );
}

function normalize(str) {
  return (str || '').normalize('NFKD');
}

function lpad(str, padString, length) {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
}
function binaryToByte(bin) {
  return parseInt(bin, 2);
}
function bytesToBinary(bytes) {
  const binaryParts = [];
  bytes.forEach(x => {
    /* console.log(
      'bytesToBinary, processing: ',
      x,
      x.toString(2),
      lpad(x.toString(2), '0', 8),
    );
    */
    binaryParts.push(lpad(x.toString(2), '0', 8));
  });
  console.log({ binaryParts });
  return binaryParts.join('');
}

async function deriveChecksumBits(entropyBuffer) {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  /*
  console.log(
    'deriveChecksumBits: ',
    { ENT, CS },
    entropyBuffer,
    entropyBuffer.toString('hex'),
  );
  */

  const entropyBuffer_u8 = Uint8Array.from(entropyBuffer);
  const entropyBuffer_u8_b64 = base64js.fromByteArray(entropyBuffer_u8);

  /* RNSimpleCrypto doesnt seem to be properly handling ArrayBuffers & Uint8Arrays */
  const hash = Buffer.from(
    await RNSimpleCrypto.SHA_b64.sha256(entropyBuffer_u8_b64),
    'base64',
  ).toString('hex');

  const normalizedHash =
    typeof hash === 'string' ? Buffer.from(hash, 'hex') : hash;

  const normalizedHashByteArray = Uint8Array
    ? Uint8Array.from(normalizedHash)
    : Array.from(normalizedHash);

  /*
  console.log(
    'normalizedHash:',
    hash,
    { normalizedHash },
    { normalizedHashByteArray },
  );
  */
  const inBinary = bytesToBinary(normalizedHashByteArray);
  const result = inBinary.slice(0, CS);
  console.log({ result });
  return result;
}

function salt(password) {
  return 'mnemonic' + (password || '');
}

function mnemonicToSeed(mnemonic, password) {
  return Promise.resolve().then(() => {
    const mnemonicBuffer = Buffer.from(normalize(mnemonic), 'utf8');
    const saltBuffer = Buffer.from(normalize(salt(password)), 'utf8');
    return pbkdf2Promise(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
  });
}

exports.mnemonicToSeed = mnemonicToSeed;
async function mnemonicToEntropy(mnemonic, wordlist) {
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }
  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }
  // convert word indices to 11 bit binary strings
  const bits = words
    .map(word => {
      const index = wordlist.indexOf(word);
      if (index === -1) {
        throw new Error(INVALID_MNEMONIC);
      }
      return lpad(index.toString(2), '0', 11);
    })
    .join('');
  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);
  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }
  const entropy = Buffer.from(entropyBytes);
  const newChecksum = await deriveChecksumBits(entropy);
  console.log({ newChecksum, checksumBits });
  if (newChecksum !== checksumBits) {
    throw new Error(INVALID_CHECKSUM);
  }
  return entropy.toString('hex');
}
exports.mnemonicToEntropy = mnemonicToEntropy;

async function entropyToMnemonic(entropy, wordlist) {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex');
  }
  wordlist = wordlist || DEFAULT_WORDLIST;
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }
  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksumBits = await deriveChecksumBits(entropy);
  console.log('entropyToMnemonic: ', { entropyBits, checksumBits });
  const bits = entropyBits + checksumBits;
  console.log({ bits });
  const chunks = bits.match(/(.{1,11})/g);
  console.log({ chunks });
  const words = chunks.map(binary => {
    const index = binaryToByte(binary);
    console.log('* index for word (' + binary + ') is: ', index);
    return wordlist[index];
  });
  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
}
exports.entropyToMnemonic = entropyToMnemonic;

async function generateMnemonic(strength, rng, wordlist) {
  strength = strength || 128;
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  rng = rng || randomBytes;
  return entropyToMnemonic(await rng(strength / 8), wordlist);
}
exports.generateMnemonic = generateMnemonic;

async function validateMnemonic_Async(mnemonic, wordlist) {
  try {
    const entropy = await mnemonicToEntropy(mnemonic, wordlist);
    // console.log('VALIDATE MNEMONIC ENTROPY IS: ', entropy);
  } catch (e) {
    // console.log('VALIDATE MNEMONIC ERROR!!!', e);
    return false;
  }
  return true;
}
exports.validateMnemonic_Async = validateMnemonic_Async;

function setDefaultWordlist(language) {
  const result = _wordlists_1.wordlists[language];
  if (result) {
    DEFAULT_WORDLIST = result;
  } else {
    throw new Error('Could not find wordlist for language "' + language + '"');
  }
}
exports.setDefaultWordlist = setDefaultWordlist;

function getDefaultWordlist() {
  if (!DEFAULT_WORDLIST) {
    throw new Error('No Default Wordlist set');
  }
  return Object.keys(_wordlists_1.wordlists).filter(lang => {
    if (lang === 'JA' || lang === 'EN') {
      return false;
    }
    return _wordlists_1.wordlists[lang].every(
      (word, index) => word === DEFAULT_WORDLIST[index],
    );
  })[0];
}
exports.getDefaultWordlist = getDefaultWordlist;

var _wordlists_2 = require('./_wordlists');
exports.wordlists = _wordlists_2.wordlists;
