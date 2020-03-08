const chai = require('chai');
const Promise = require('bluebird');
const readFile = Promise.promisify(require("fs").readFile);
const path = require('path');
const _ = require('lodash');

const expect = require('chai').expect;

const oadacerts = require('@oada/oada-certs');
const tSig = require('../trellisfw-signatures');

let keys = false;
const unsigned = require('./unsigned.json');


describe('trellisfw-signatures', function() {

  before(async () => {
    keys = await oadacerts.createKey();
  });

  describe('#hashJSON', function() {
    it('should produce a proper SHA256 hash of an object', () => {
      const obj = { key1: 'hello', key2: 'world', key3: 1, key4: 1.2, 'key"5"': 'tricky one with "quotes', key6: 'apo\'strophe' };
      const hashinfo = tSig.hashJSON(obj);
      expect(hashinfo).to.be.an('object');
      expect(hashinfo.alg).to.equal('SHA256');
      expect(hashinfo.hash).to.be.a('string');
      expect(hashinfo.hash).to.have.lengthOf(64);
    });

    it('should produce the same hash regardless of key creation order', () => {
      const obj1 = { key1: 'hello', key2: 'world', key3: 1, key4: 1.2, 'key"5"': 'tricky one with "quotes', key6: 'apo\'strophe' };
      const obj2 = _.reduce(_.reverse(_.keys(obj1)), (acc,k) => {
        acc[k] = obj1[k]; 
        return acc
      }, {});
      const hashinfo1 = tSig.hashJSON(obj1);
      const hashinfo2 = tSig.hashJSON(obj2);
      expect(hashinfo1).to.deep.equal(hashinfo2);
    });

    it('should omit OADA keys by default', () => {
      const obj = { _id: 'theone', _meta: { _id: 'resources/theone/_meta', _rev: 1 }, _rev: 1, key1: 'val1' };
      const hash1 = tSig.hashJSON(obj);
      const obj2 = _.cloneDeep(obj);
      delete obj2._id;
      delete obj2._meta;
      delete obj2._rev;
      const hash2 = tSig.hashJSON(obj2);
      expect(hash1).to.deep.equal(hash2);
    });
    it('should not omit OADA keys if option says no to', () => {
      const obj = { _id: 'theone', _meta: { _id: 'resources/theone/_meta', _rev: 1 }, _rev: 1, key1: 'val1' };
      const hash1 = tSig.hashJSON(obj, { keepOADAKeys: true });
      const hash2 = tSig.hashJSON(obj, { keepOADAKeys: false });
      expect(hash1).to.not.deep.equal(hash2);
    });
  });


  describe('#sign', function() {
    it('should add a signatures key to an object', async () => {
      const signed = await tSig.sign(unsigned, keys.private);
      expect(signed).to.have.property('signatures');
      expect(signed.signatures).to.be.an('array');
      expect(signed.signatures).to.have.lengthOf(1);
    });
    it('should preserve signer info', async () => {
      const signer = { name: 'OATS', url: 'http://oatscenter.org' };
      const signed = await tSig.sign(unsigned, keys.private, { 
        signer,
      });
      const {trusted, valid, payload, details} = await oadacerts.validate(signed.signatures[0]);
      expect(payload).to.be.an('object');
      expect(payload.signer).to.deep.equal(signer);
    });
    it('should preserve signature type', async () => {
      const type = 'transcription';
      const signed = await tSig.sign(unsigned, keys.private, { 
        header: { jwk: keys.public },
        type,
      });
      const {trusted, valid, payload, header, details} = await oadacerts.validate(signed.signatures[0]);
      expect(payload).to.be.an('object');
      expect(payload.type).to.deep.equal(type);
    });
    it('should maintain jku and kid in header if passed on options', async () => {
      const signed = await tSig.sign(unsigned, keys.private, { 
        header: { 
          jku: 'https://nowhere.example.com', 
          kid: '1' 
        }
      });
      const {trusted, valid, payload, header, details} = await oadacerts.validate(signed.signatures[0]);
      expect(trusted).to.equal(false);
      expect(valid).to.equal(true);
      expect(payload.hashinfo).to.deep.equal(tSig.hashJSON(unsigned));
      expect(payload.iat).to.be.below(Date.now());
      expect(header.kid).to.equal('1');
      expect(header.jku).to.equal('https://nowhere.example.com');
    });
  });

  describe('#verify', function() {
    it('should verify a properly signed object', async () => {
      const unsigned = { key1: 'hello' };
      const signed = await tSig.sign(unsigned, keys.private);
      const { trusted, valid, unchanged, original, payload, header, details} = await tSig.verify(signed);
      expect(trusted).to.equal(false);
      expect(valid).to.equal(true);
      expect(unchanged).to.equal(true);
      expect(original).to.deep.equal(unsigned);
      expect(payload).to.be.an('object');
      expect(payload.hashinfo).deep.equal(tSig.hashJSON(unsigned));
      expect(header).to.be.an('object');
      expect(header.jwk).to.be.an('object'); // oada-certs always puts JWK on the header
    });

    it('should detect a change to content after signing', async () => {
      const signed = await tSig.sign(unsigned, keys.private);
      signed.anewkey = 'gotcha';
      const { unchanged } = await tSig.verify(signed);
      expect(unchanged).to.equal(false);
    });

  });
});
