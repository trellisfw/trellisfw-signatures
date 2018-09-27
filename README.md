# trellisfw-signatures #

Create and verify RS256 based JWT oauth-jwt-bearer client authentications.

## Installation ##
```shell
npm install @trellisfw/signatures
```

## Require Usage ##
```javascript
var tSignature = require('@trellisfw/signatures');
```

## API ##

### generate(audit, key, headers) ###
Generate a signed audit with the given headers and the client's private key. The `generate` function appends a Json Web Token (JWT) to the audit's `signatures`.

#### Parameters ####
`audit` *{Object}* A food safety audit per the Trellis framework.

`key` *{PEM JWK}* The key used to sign the audit. Supported key types include those supported by [kjur/jsrsasign]'s `KJUR.KEYUTIL.getKey` function. If the JWK has a `kid` property it will be
included in the client assertion header.

`headers` *{Object}* The `headers` parameter is passed directly to
[kjur/jsrsasign]. This module will not allow the caller to override the properties required by the [jwt-bearer][jwt-bearer] RFC. You can add properties to the header and claim set with the following sub-objects:


[kjur/jsrsasign]: https://github.com/kjur/jsrsasign
[trellisfw]: https://github.com/trellisfw/trellisfw-docs
