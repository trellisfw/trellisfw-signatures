# trellisfw-signatures #

Create and verify RS256 based JWT oauth-jwt-bearer client authentications.

## Installation ##
```shell
npm install @trellisfw/signatures
```

## Require Usage ##
```javascript
const tsig = require('@trellisfw/signatures');
const objToSign = {
  "hello": "world"
};
const key = require('./jwkprivatekey.json');

// Sign an object:
try {
  const signed = await tsig.sign(objToSign, key);
  // returns a new copy of objToSign with signature added
  console.log('Successfully signed object.  Signed document = ', signed);
} catch(err ){
  console.log('Failed to sign object.  Error was: ", err);
}

// Verify the last (latest) signature in the signatures array on a signed object:
try {
  const { trusted, valid, payload, unchanged, details } = await tsig.verify(signedObj);
  console.log('Was signature signed by a trusted key: ', trusted);
  console.log('Was signature a valid JWT according to the key used to sign it: ', valid);
  console.log('Was the document changed since the signature was applied: ', unchanged);
  console.log('The payload of the signature was: ', payload);
  console.log('The library told us these things about the decoding process: ', details);
} catch(err) {
  console.log('Signature verification failed.');
}

```

## API ##

### _async_ `sign(jsonobject, privateJWK, headers)` ###
Generate a signed `jsonobject` with the given headers and the client's private key. The `sign` function appends a Json Web Token (JWT) to the jsonobject's `signatures` key, or creates a signatures key if one is not there.

You can generate a privateJWK with [https://github.com/oada/oada-certs], and the `keys` library from `oada-certs` is 
exposed as `keys` in this library for convenience, so you can also use that to make keys.

#### Parameters ####
`jsonobject` *{Object}* Any JSON object

`key` *{JWK}* The key used to sign the audit, as a JWK.

`headers` *{Object}* The `headers` parameter is sent on to oada-certs to be used
in the signature process.  The `typ` and `alg` keys are retained if present.  Note If
there is a key id in the headers (`headers.kid`), and there is also a `kid` in the
JWK passed as the signing key, the one in the headers will override the
one in the key.


### _async_ `verify(jsonobject,options)`
Determine if the last item in a jsonobject's signatures key is trusted, valid, and if the document
itself is unchanged since the signature was applied.  Options are passed to `oada-certs.validate`
once the Trellis trusted list has been added.

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


### serliaizeJSON(obj)
Returns a consistent string representation for any JSON object by lexically sorting keys.

### hashJSON(obj)
Uses `serializeJSON` to convert `obj` to a string, removes any OADA-specific keys like `_id`, `_rev`, `_meta`,
then hashes the resulting string.

Returns `{ alg, hash }`

### keys
Exports `keys` `@oada/oada-certs` for convenience.

### jose
Exports `jose` from `@oada/oada-certs` for convenience.

[trellisfw]: https://github.com/trellisfw/trellisfw-docs
