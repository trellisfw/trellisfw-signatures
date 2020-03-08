# trellisfw-signatures #

Create and verify RS256 based JWT oauth-jwt-bearer client authentications.

## Installation ##
```shell
npm install @trellisfw/signatures
```

## Require Usage ##
```javascript
var tSignature = require('@trellisfw/signatures');
const objToSign = {
  "hello": "world"
};
const key = require('./jwkprivatekey.json');

// Sign an object:
try {
  tSignature.sign(objToSign, key);
  // This mutates objToSign by adding a `signatures` key as an array.
  console.log('Successfully signed object.  Singed document = ', objToSign);
} catch(err ){
  console.log('Failed to sign object.  Error was: ", err);
}

// Verify the last (latest) signature in the signatures array on a signed object:
const signedObj = objToSign; // mutated above to add signatures key
try {
  const { trusted, valid, payload, unchanged, messages } = tSignature.validate(signedObj);
  console.log('Was signature signed by a trusted key: ', trusted);
  console.log('Was signature a valid JWT according to the key used to sign it: ', valid);
  console.log('Was the document changed since the signature was applied: ', unchanged);
  console.log('The payload of the signature was: ', payload);
  console.log('The library told us these things about the decoding process: ', messages);
} catch(err) {
  console.log('Signature verification failed.');
}

```

## API ##

### sign(jsonobject, key, headers) ###
Generate a signed jsonobject with the given headers and the client's private key. The `sign` function appends a Json Web Token (JWT) to the jsonobject's `signatures` key.

#### Parameters ####
`jsonobject` *{Object}* Any JSON object, such as a food safety audit.

`key` *{JWK}* The key used to sign the audit, as a JWK.

`headers` *{Object}* The `headers` parameter is sent on to oada-certs to be used
in the signature process.  The `typ` and `alg` keys are retained if present.  Note If
there is a key id in the headers (`headers.kid`), and there is also a `kid` in the
JWK passed as the signing key, the one in the headers will override the
one in the key.


### validate(jsonobject,options)
Determine if the last item in a jsonobject's signatures key is trusted, valid, and if the document
itself is unchanged since the signature was applied.

Returns { trusted, valid, unchanged, payload, messages }
- `valid`: true if signature is a valid JWT and a public key is available to check it against.
- `trusted`: true if signature is valid and was signed with a JWK from the trusted list.
- `unchanged`: true if the signature is valid and the payload hashes to the same value as the current document.
- `payload`: the actual decoded payload of the signature.
- `messages`: an array of debugging messages designed to help you figure out why the library
   has made the determinations that it returns.

#### Parameters ####
- `jsonobject`: an object with a signatures key that is an array with at least one JWT signature in it.
- `options`: object with options to pass directly to [oada-certs](https://github.com/oada/oada-cerst) library.  
   Please refer to the docuentation for oada-certs for details, but this can include things like alternate
   trusted lists, etc.  Please note that this library will always pre-prend the main Trellis
   trusted list onto the front of any additional trusted lists that are passed in options.

[trellisfw]: https://github.com/trellisfw/trellisfw-docs
