const chai = require('chai');
const Promise = require('bluebird');
const KJUR = require('jsrsasign');
const readFile = Promise.promisify(require("fs").readFile);
const path = require('path');

const assert = require('chai').assert;
const expect = require('chai').expect;
const should = require('chai').should;

const tSig = require('../trellisfw-signatures');

const unsignedAudit = readFile(path.join(__dirname, '/audits/unsignedAudit.json'), 'utf8');
const signedAudit = readFile(path.join(__dirname, '/audits/signedAudit.json'), 'utf8');

const keyInfo = {
  "kid": "SignatureService",
  "alg": "RS256",
  "kty": "RSA",
  "typ": "JWT",
  "jku": "https://raw.githubusercontent.com/fpad/trusted-list/master/jku-test/some-other-jku-not-trusted.json"
}

describe('trellisfw-signatures', function() {
  describe('generate()', function() {
    it('Keys are strings', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8');
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8');
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then((signatures) => {
          //Audit should now have signatures
          expect(audit).to.have.property('signatures');
          expect(audit.signatures).to.be.an('array');
          expect(audit.signatures).to.have.lengthOf(1);
        });
      });
    });
    it('Keys are RSAKeys', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getKey(key);
      });
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getKey(key);
      });;
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then((signatures) => {
          //Audit should now have signatures
          expect(audit).to.have.property('signatures');
          expect(audit.signatures).to.be.an('array');
          expect(audit.signatures).to.have.lengthOf(1);
        });
      });
    });
    it('Keys are JWTs', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getJWKFromKey(KJUR.KEYUTIL.getKey(key));
      });
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getJWKFromKey(KJUR.KEYUTIL.getKey(key));
      });;
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then((signatures) => {
          //Audit should now have signatures
          expect(audit).to.have.property('signatures');
          expect(audit.signatures).to.be.an('array');
          expect(audit.signatures).to.have.lengthOf(1);
        });
      });
    });
  });
  describe('verify()', function() {

  });
  describe('generate() and verify()', function() {
    it('Keys are strings', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8');
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8');
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then(() => {
          //Verify signed audit
          return tSig.verify(audit, {allowUntrusted: true}).then((response) => {
            expect(response).to.equal(true);
          })
        });
      });
    });
    it('Keys are RSAKeys', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getKey(key);
      });
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getKey(key);
      });;
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then(() => {
          //Verify signed audit
          return tSig.verify(audit, {allowUntrusted: true}).then((response) => {
            expect(response).to.equal(true);
          })
        });
      });
    });
    it('Keys are JWTs', function() {
      const publicKey = readFile(path.join(__dirname, '/keys/public.pub'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getJWKFromKey(KJUR.KEYUTIL.getKey(key));
      });
      const privateKey = readFile(path.join(__dirname, '/keys/private_unencrypted.pem'), 'utf8').then((key) => {
        return KJUR.KEYUTIL.getJWKFromKey(KJUR.KEYUTIL.getKey(key));
      });;
      return Promise.join(unsignedAudit, publicKey, privateKey, keyInfo, (unsignedAudit, publicKey, privateKey, {kid, alg, kty, typ, jku}) => {
        const headers = { kid, alg, kty, typ, jku, jwk: publicKey}
        var audit = JSON.parse(unsignedAudit);
        return tSig.generate(audit, privateKey, headers).then(() => {
          //Verify signed audit
          return tSig.verify(audit, {allowUntrusted: true}).then((response) => {
            expect(response).to.equal(true);
          })
        });
      });
    });
  });
});
