'use strict'
const pkg = require('./package.json');
const sha256 = require('js-sha256');
const oadacerts = require('@oada/oada-certs');
const _ = require('lodash');
const debug = require('debug');
const warn = debug('trellisfw-signatures:warn');
const trace = debug('trellisfw-signatures:trace');

module.exports = {
  sign,
  verify,
  serializeJSON,
  hashJSON,
}

const TRELLIS_TRUSTED_LIST = 'https://raw.githubusercontent.com/trellisfw/trusted-list/master/keys.json';
const OADA_CERTS_OPTIONS = {
  additionalTrustedListURIs: [ TRELLIS_TRUSTED_LIST ],
  disableDefaultTrustedListURI: true,  // don't use the OADA built-in one for these
};

// Remove a signature from the list, or remove signatures key entirely if empty after pop
function popSignature(testobj) {
  testobj = _.cloneDeep(testobj);
  if (!testobj || !testobj.signatures || testobj.signatures.length < 1) return testobj;
  trace('popSignature: before pop, testobj.signatures = ', testobj.signatures);
  // Remove the last signature in the signatures key array for reconstruction.
  testobj.signatures.pop();
  if (testobj.signatures.length < 1) {
    delete testobj.signatures;
  }
  trace('popSignature: after pop, testobj.signatures = ', testobj.signatures);
  return testobj;
}

// Adds a signature to the list of existing signatures, or adds the signatures
// list if this is the first one.
function pushSignature(testobj, sig) {
  testobj = _.cloneDeep(testobj);
  if (!testobj) return testobj;
  if (!testobj.signatures) testobj.signatures = [];
  testobj.signatures.push(sig);
  return testobj;
}


// This function verifies the given object. The object's signature should contain the public key source
// necessary to verify itself (either JWK or JKU).
// Returns: { trusted, valid, unchanged, payload, header, details, original }
// - trusted: true|false - is signer considered trusted
// - valid: true|false - is the signature itself a valid JWT that can be decoded and the signature matches
// - unchanged: true|false - have the contents been modified since signing
// - payload: the payload of the signature
// - original: the original JSON object before signing (i.e. with the latest signature popped off)
// - details: if verification fails, look here for an array of helpful debugging messages about the process
async function verify(testobj, options) {
  options = options || {};
  // Check that a signature is present and parse out the given JWT headers
  if (!testobj) throw new Error('No object passed.')
  if (!testobj.signatures) throw new Error('Object has no signatures to be verified.')
  if (testobj.signatures.length === 0) throw new Error('Object has no signatures.')
  const sig = testobj.signatures[testobj.signatures.length-1]

  const result = await oadacerts.validate(sig,_.merge(options, OADA_CERTS_OPTIONS));
  trace('verify: result from oadacerts = ', result);
  const { trusted, valid, payload, header, details } = result;
  const original = popSignature(testobj);

  let unchanged = false;
  if (payload && payload.hashinfo && payload.hashinfo.hash) {
    const ohashinfo = hashJSON(original);
    trace('verify: checking unchanged, payload hash = ', payload.hashinfo.hash, ', original hash = ', ohashinfo.hash);
    unchanged = (payload.hashinfo.hash === ohashinfo.hash);
  }

  return {trusted, valid, unchanged, payload, header, original, details};
}

// This function accepts an input object along with any JWT headers necessary to
// construct a JWT and appends an additional signature to the signatures key of
// the object.  To be trusted, the public version of your private key must be on 
// the trusted list, or a jku and kid where that public version of your private key can be
// found must be in options.header.
// Options: 
// - signer: { name: 'name of signer', url: 'URL of signer homepage' }
//   in the future, signer could be like an oada dynamic client certificate, signed by someone trusted
// - type: 'transcription', 'original' -> type of signature
// - header: header for the JWT, passed down to oada-certs.  Include things like jku, jwk, kid
async function sign(original, prvJwk, options) {
  if (!prvJwk) throw new Error('Private key as a JWK required to sign an object.');
  options = options || {};
  options.header = options.header || {};
  if (options.headers) throw new Error('You passed options.headers, but I think you meant options.header');

  const payload = { 
    version: pkg.version,
    iat: Math.floor(Date.now() / 1000),
    hashinfo: hashJSON(original),
  };
  if (options.signer) payload.signer = options.signer;
  if (options.type) payload.type = options.type;

  const sig = await oadacerts.sign(payload, prvJwk, options);
  if (!sig) throw new Error('Signature could not be generated');

  return pushSignature(original, sig);
}

function serializeJSON(obj) {

  if (typeof obj === 'number') {
    const str = obj.toString();
    if (str.match(/\./)) {
      warn('You cannot serialize a floating point number with a hashing function and expect it to work consistently across all systems.  Use a string.');
    }
    // Otherwise, it's an int and it should serialize just fine.
    return str;
  }
  if (typeof obj === 'string') return '"'+obj+'"';
  if (typeof obj === 'boolean') return (obj ? 'true' : 'false');
  // Must be an array or object
  var isarray = _.isArray(obj);
  var starttoken = isarray ? '[' : '{';
  var endtoken = isarray ? ']' : '}';

  if (!obj) return 'null';

  const keys = _.keys(obj).sort(); // you can't have two identical keys, so you don't have to worry about that.

  return starttoken
    + _.reduce(keys, function(acc,k,index) {
      if (!isarray) acc += '"'+k+'":'; // if an object, put the key name here
      acc += serializeJSON(obj[k]);
      if (index < keys.length-1) acc += ',';
      return acc;
    },"")
    + endtoken;
}

// Options:
// - keepOADAKeys: true|false, default: false.  Default gets rid of the OADA keys at top level of obj: _id, _meta, _rev
function hashJSON(obj, options) {
  options = options || {};
  if (!options.keepOADAKeys) {
    obj = _.omit(obj, ['_id', '_meta', '_rev']);
  }
  const ser = serializeJSON(obj);
  trace('hashJSON: serialized JSON string = ', ser, ' for object ', obj);
  return {
    alg: 'SHA256',
    hash: sha256(ser),
  };
}
