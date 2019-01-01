/// <reference path="node_modules/tns-platform-declarations/android.d.ts" />

import {
  KeyHelperDef,
  UtilDef,
  InMemorySignalProtocolStoreDef,
  TypeDef,
  ISignalProtocolStore,
  CoreDef,
  SessionCipherDef,
  IdentityKeyStoreDef,
  SessionBuilderDef,
  SessionStoreDef,
  PreKeyStoreDef,
  SignedPreKeyStoreDef,
  PreKeyBundleDef,
  ClientInfoDef,
  ClientDef,
  CurveDef,
  MemorySignalProtocolStoreDef } from './libsignal-protocol.common';

declare var org: any;
declare var java: any;

export namespace LibsignalProtocol {

  export class MemorySignalProtocolStore implements ISignalProtocolStore {
    Direction: any;
    MemoryStore: any;

    constructor(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number) {
      this.Direction = {
        SENDING: 1,
        RECEIVING: 2,
      };

      this.MemoryStore = new org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(identityKeyPair, registrationId);
    }

    public getIdentityKeyPair(): TypeDef.IdentityKeyPair {
      return this.MemoryStore.getIdentityKeyPair();
    }

    public getLocalRegistrationId(): number {
      return this.MemoryStore.getLocalRegistrationId();
    }

    public saveIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey): boolean {
      return this.MemoryStore.saveIdentity(address, identityKey);
    }

    public isTrustedIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey, direction: any): boolean {
      return this.MemoryStore(address, identityKey, direction);
    }

    public getIdentity(address: TypeDef.SignalProtocolAddress): TypeDef.IdentityKey {
      return this.MemoryStore.getIdentity(address);
    }

    public loadPreKey(preKeyId: number): TypeDef.PreKeyRecord {
      return this.MemoryStore.loadPreKey(preKeyId);
    }

    public storePreKey(preKeyId: number, record: TypeDef.PreKeyRecord): void {
      return this.MemoryStore.storePreKey(preKeyId, record);
    }

    public containsPreKey(preKeyId: number): boolean {
      return this.MemoryStore.containsPreKey(preKeyId);
    }

    public removePreKey(preKeyId: number): void {
      return this.MemoryStore.removePreKey(preKeyId);
    }

    public loadSession(address: TypeDef.SignalProtocolAddress): TypeDef.SessionRecord {
      return this.MemoryStore.loadSession(address);
    }

    public getSubDeviceSessions(name: string): java.util.List<java.lang.Integer> {
      return this.MemoryStore.getSubDeviceSessions(name);
    }

    public storeSession(address: TypeDef.SignalProtocolAddress, record: TypeDef.SessionRecord): void {
      return this.MemoryStore.storeSession(address, record);
    }

    public containsSession(address: TypeDef.SignalProtocolAddress): boolean {
      return this.MemoryStore.containsSession(address);
    }

    public deleteSession(address: TypeDef.SignalProtocolAddress): void {
      return this.MemoryStore.deleteSession(address);
    }

    public deleteAllSessions(name: string): void {
      return this.MemoryStore.deleteAllSessions(name);
    }

    public loadSignedPreKey(signedPreKeyId: number): TypeDef.SignedPreKeyRecord {
      return this.MemoryStore.loadSignedPreKey(signedPreKeyId);
    }

    public loadSignedPreKeys(): TypeDef.SignedPreKeyRecord[] {
      return this.MemoryStore.loadSignedPreKeys();
    }//java.util.List<TypeDef.SignedPreKeyRecord>;

    public storeSignedPreKey(signedPreKeyId: number, record: TypeDef.SignedPreKeyRecord): void {
      return this.MemoryStore.storeSignedPreKey(signedPreKeyId, record);
    }

    public containsSignedPreKey(signedPreKeyId: number): boolean {
      return this.MemoryStore.containsSignedPreKey(signedPreKeyId);
    }

    public removeSignedPreKey(signedPreKeyId: number): void {
      return this.MemoryStore.removeSignedPreKey(signedPreKeyId);
    }
  }

  export class SessionCipher implements SessionCipherDef {
    sessionStore: SessionStoreDef;
    identityKeyStore: IdentityKeyStoreDef;
    sessionBuilder: SessionBuilderDef;
    preKeyStore: PreKeyStoreDef;
    remoteAddress: TypeDef.SignalProtocolAddress;
    CipherStore: any;

    constructor(store: MemorySignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress) {
      this.CipherStore = new org.whispersystems.libsignal.SessionCipher(store, remoteAddress);
    }

    public encrypt(paddedMessage: any): any {
      return this.CipherStore.encrypt(paddedMessage);
    }

    public decrypt(ciphertext: any, callback?: any): any {
      if (typeof callback === 'undefined') return this.CipherStore.decrypt(ciphertext, callback);
      return this.CipherStore.decrypt(ciphertext);
    }
  }
  
  export class InMemorySignalProtocolStore implements InMemorySignalProtocolStoreDef {
    Direction: any;
    store: any;

    constructor() {
      this.store = {};
      this.Direction = {
        SENDING: 1,
        RECEIVING: 2,
      };
    }

    public getIdentityKeyPair(): Promise<any> {
      return Promise.resolve(this.get('identityKey'));
    }
    
    public getLocalRegistrationId(): Promise<any> {
      return Promise.resolve(this.get('registrationId'));
    }

    public put(key: string, value: string): void {
      if (key === undefined || value === undefined || key === null || value === null)
        throw new Error('Tried to store undefined/null');
      this.store[key] = value;
    }

    public get(key: string, defaultValue?: any): any {
      if (key === null || key === undefined)
        throw new Error('Tried to get value for undefined/null key');
      if (key in this.store) {
        return this.store[key];
      } else {
        return defaultValue;
      }
    }

    public remove(key: string): void {
      if (key === null || key === undefined)
        throw new Error('Tried to remove value for undefined/null key');
      delete this.store[key];
    }

    public isTrustedIdentity(identifier, identityKey, direction): Promise<any> {
      if (identifier === null || identifier === undefined) {
        throw new Error('tried to check identity key for undefined/null key');
      }
      if (!(identityKey instanceof ArrayBuffer)) {
        throw new Error('Expected identityKey to be an ArrayBuffer');
      }
      let trusted = this.get('identityKey' + identifier);
      if (trusted === undefined) {
          return Promise.resolve(true);
      }
      return Promise.resolve(LibsignalProtocol.Util.isEqualString(identityKey, trusted));
    }

    public loadIdentityKey(identifier): Promise<any> {
      if (identifier === null || identifier === undefined)
        throw new Error('Tried to get identity key for undefined/null key');
      return Promise.resolve(this.get('identityKey' + identifier));
    }

    public saveIdentity(identifier: string, identityKey): Promise<any> {
      if (identifier === null || identifier === undefined)
        throw new Error('Tried to put identity key for undefined/null key');
      if (typeof identifier !== 'string' || !identifier.match(/.*\.\d+/)) {
        throw new Error('Invalid SignalProtocolAddress string');
      }

      // console.log('SAVE IDENTITY', identifier);
      
      let parts = identifier.split('.');
      let address = new org.whispersystems.libsignal.SignalProtocolAddress(parts[0], parseInt(parts[1]));

      let existing = this.get('identityKey' + address.getName());
      this.put('identityKey' + address.getName(), identityKey);

      // console.log('...equal?', LibsignalProtocol.Util.isEqualString(identityKey, existing));
      if (existing && !LibsignalProtocol.Util.isEqualString(identityKey, existing)) {
        return Promise.resolve(true);
      } else {
        return Promise.resolve(false);
      }
    }

    /* Returns a prekeypair object or undefined */
    public loadPreKey(keyId): Promise<any> {
      let res = this.get('25519KeypreKey' + keyId);
      if (res !== undefined) {
        res = {pubKey: res.pubKey, privKey: res.privKey};
      }
      return Promise.resolve(res);
    }

    public storePreKey(keyId, keyPair): Promise<any> {
      return Promise.resolve(this.put('25519KeypreKey' + keyId, keyPair));
    }

    public removePreKey(keyId): Promise<any> {
      return Promise.resolve(this.remove('25519KeypreKey' + keyId));
    }

    /* Returns a signed keypair object or undefined */
    public loadSignedPreKey(keyId): Promise<any> {
      let res = this.get('25519KeysignedKey' + keyId);
      if (res !== undefined) {
        res = {pubKey: res.pubKey, privKey: res.privKey};
      }
      return Promise.resolve(res);
    }

    public storeSignedPreKey(keyId, keyPair): Promise<any> {
      return Promise.resolve(this.put('25519KeysignedKey' + keyId, keyPair));
    }

    public removeSignedPreKey(keyId): Promise<any> {
      return Promise.resolve(this.remove('25519KeysignedKey' + keyId));
    }

    public loadSession(identifier): Promise<any> {
      return Promise.resolve(this.get('session' + identifier));
    }

    public storeSession(identifier, record): Promise<any> {
      return Promise.resolve(this.put('session' + identifier, record));
    }

    public removeSession(identifier): Promise<any> {
      return Promise.resolve(this.remove('session' + identifier));
    }

    public removeAllSessions(identifier): Promise<any> {
      for (let id in this.store) {
        if (id.startsWith('session' + identifier)) {
          delete this.store[id];
        }
      }
      return Promise.resolve();
    }
  }

  export class Util implements UtilDef {
    public static base64Encode(mixed: any): string {
      return android.util.Base64.encodeToString(mixed, android.util.Base64.NO_WRAP);
    }
  
    public static base64Decode(base64Str: any): native.Array<number> {
      return android.util.Base64.decode(base64Str, android.util.Base64.NO_WRAP);
    }

    public static base64ToArrayBuffer(base64: string): ArrayBuffer {
      let binary_string = Util.atob(base64);
      let len = binary_string.length;
      let bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
          bytes[i] = binary_string.charCodeAt(i);
      }
      return bytes.buffer;
    }
  
    public static arrayBufferToBase64(buffer: Iterable<number>): string {
      let binary = '';
      let bytes = new Uint8Array(buffer);
      let len = bytes.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return Util.btoa(binary);
    }

    public static atob(str: string) {
      // base64 character set, plus padding character (=)
      var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      // Regular expression to check formal correctness of base64 encoded strings
      b64re = /^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/;
    
      // atob can work with strings with whitespaces, even inside the encoded part,
      // but only \t, \n, \f, \r and ' ', which can be stripped.
      str = String(str).replace(/[\t\n\f\r ]+/g, "");
      if (!b64re.test(str))
          throw new TypeError("Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded.");
    
      // Adding the padding if missing, for semplicity
      str += "==".slice(2 - (str.length & 3));
      var bitmap, result = "", r1, r2, i = 0;
      for (; i < str.length;) {
          bitmap = b64.indexOf(str.charAt(i++)) << 18 | b64.indexOf(str.charAt(i++)) << 12
                  | (r1 = b64.indexOf(str.charAt(i++))) << 6 | (r2 = b64.indexOf(str.charAt(i++)));
    
          result += r1 === 64 ? String.fromCharCode(bitmap >> 16 & 255)
                  : r2 === 64 ? String.fromCharCode(bitmap >> 16 & 255, bitmap >> 8 & 255)
                  : String.fromCharCode(bitmap >> 16 & 255, bitmap >> 8 & 255, bitmap & 255);
      }
      return result;
    };
      
    public static btoa(str: string) {
      // base64 character set, plus padding character (=)
      var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      // Regular expression to check formal correctness of base64 encoded strings
      b64re = /^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/;
    
      str = String(str);
      var bitmap, a, b, c,
          result = "", i = 0,
          rest = str.length % 3; // To determine the final padding
    
      for (; i < str.length;) {
          if ((a = str.charCodeAt(i++)) > 255
                  || (b = str.charCodeAt(i++)) > 255
                  || (c = str.charCodeAt(i++)) > 255)
              throw new TypeError("Failed to execute 'btoa' on 'Window': The string to be encoded contains characters outside of the Latin1 range.");
    
          bitmap = (a << 16) | (b << 8) | c;
          result += b64.charAt(bitmap >> 18 & 63) + b64.charAt(bitmap >> 12 & 63)
                  + b64.charAt(bitmap >> 6 & 63) + b64.charAt(bitmap & 63);
      }
    
      // If there's need of padding, replace the last 'A's with equal signs
      return rest ? result.slice(0, rest - 3) + "===".substring(rest) : result;
    };

    public static toString(value: any) {
      try {
        if (value === null) return '';
        else if (typeof value === 'string') return value;
        else if (typeof value === 'number') return Number(value).toString();
        else if (typeof value === 'function') return value.toString();
        else if (typeof value === 'object') {
          if (value.hasOwnProperty('length')) return value.toString();
          else return JSON.stringify(value);
        }
        else return java.lang.String.valueOf(value);
      } catch (err) {
        console.log(`Unable to convert value.toString`);
        return '';
      }
    }

    public static isEqualString(value: any, compared: any) {
      return !!(LibsignalProtocol.Util.toString(value) === LibsignalProtocol.Util.toString(compared));
    }
  }

  export class Core implements CoreDef {
    static importPreKeyRecord(serialized: any): TypeDef.PreKeyRecord {
      try {
        return new org.whispersystems.libsignal.state.PreKeyRecord(serialized);
      } catch (err) {
        console.log('ERROR -- Unable to import PreKeyRecord');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static importSignedPreKeyRecord(serialized: any): TypeDef.SignedPreKeyRecord {
      try {
        return new org.whispersystems.libsignal.state.SignedPreKeyRecord(serialized);
      } catch (err) {
        console.log('ERROR -- Unable to import SignedPreKeyRecord');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static importSignedPreKey(serialized: any): TypeDef.SignedPreKeyRecord {
      return new org.whispersystems.libsignal.state.SignedPreKeyRecord(serialized);
    }

    static importIdentityKey(serialized: any): TypeDef.IdentityKey {
      try {
        return new org.whispersystems.libsignal.IdentityKey(serialized, 0);
      } catch (err) {
        console.log('ERROR -- Unable to import IdentityKey');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static importIdentityKeyPair(serialized: any): TypeDef.IdentityKeyPair {
      try {
        return new org.whispersystems.libsignal.IdentityKeyPair(serialized);
      } catch (err) {
        console.log('ERROR -- Unable to import IdentityKeyPair');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static importPublicKey(serialized: any): TypeDef.ECPublicKey {
      try {
        return org.whispersystems.libsignal.ecc.Curve.decodePoint(serialized, 0);
      } catch (err) {
        console.log('ERROR -- Unable to import ECPublicKey');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static createPreKeySignalMessage(serialized: any): TypeDef.PreKeySignalMessage {
      try {
        return new org.whispersystems.libsignal.protocol.PreKeySignalMessage(serialized);
      } catch (err) {
        console.log('ERROR -- Unable to create PreKeySignalMessage');
        // console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static createSignalMessage(serialized: any): any {
      try {
        return new org.whispersystems.libsignal.protocol.SignalMessage(serialized);
      } catch (err) {
        console.log('ERROR -- Unable to create SignalMessage');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static createPreKeyRecord(id: number, keyPair: TypeDef.ECKeyPair): TypeDef.PreKeyRecord {
      return new org.whispersystems.libsignal.state.PreKeyRecord(id, keyPair);
    }

    static createSignedPreKeyRecord(id: number, timestamp: number, keyPair: TypeDef.ECKeyPair, signature: any): TypeDef.SignedPreKeyRecord {
      return new org.whispersystems.libsignal.state.SignedPreKeyRecord(id, timestamp, keyPair, signature);
    }

    static createSignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): ISignalProtocolStore {
      return new org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(identityKeyPair, registrationId);
    }

    static createTestSignalProtocolStore(): ISignalProtocolStore {
      function generateRegistrationId(): number {
        return  org.whispersystems.libsignal.util.KeyHelper.generateRegistrationId(false);
      }

      function generateIdentityKeyPair(): TypeDef.IdentityKeyPair {
        let keyPair: TypeDef.ECKeyPair = Curve.generateKeyPair();
        let publicKey: TypeDef.IdentityKey = new org.whispersystems.libsignal.IdentityKey(keyPair.getPublicKey());
        return new org.whispersystems.libsignal.IdentityKeyPair(publicKey, keyPair.getPrivateKey());
      }

      return new org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(generateIdentityKeyPair(), generateRegistrationId());
    }

    static createIdentityKeyPair(publicKey: TypeDef.IdentityKey, privateKey: TypeDef.ECPrivateKey): TypeDef.IdentityKeyPair {
      return new org.whispersystems.libsignal.IdentityKeyPair(publicKey, privateKey);
    }

    static createIdentityKey(publicKey: TypeDef.ECPublicKey): TypeDef.IdentityKey {
      return new org.whispersystems.libsignal.IdentityKey(publicKey);
    }

    static createSessionBuilder(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionBuilderDef {
      try {
        return new org.whispersystems.libsignal.SessionBuilder(store, address);
      } catch (err) {
        console.log('ERROR -- Unable to create SessionBuilder');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static createSessionCipher(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionCipherDef {
      return new org.whispersystems.libsignal.SessionCipher(store, address);
    }

    static createMemorySignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): ISignalProtocolStore {
      return new org.whispersystems.libsignal.state.impl.InMemorySignalProtocolStore(identityKeyPair, registrationId);
    }
    
    static createSessionRecord(): TypeDef.SessionRecord {
      return new org.whispersystems.libsignal.state.SessionRecord();
    }

    static createSignalProtocolAddress(registrationId: number | string, deviceId: number): TypeDef.SignalProtocolAddress {
      try {
        return new org.whispersystems.libsignal.SignalProtocolAddress(registrationId + '', deviceId);
      } catch (err) {
        console.log('ERROR -- Unable to create SignalProtocolAddress');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static createPreKeyBundle(registrationId: number | string, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any, identityKey: TypeDef.IdentityKey | any): PreKeyBundleDef {
      try {
        return new org.whispersystems.libsignal.state.PreKeyBundle(registrationId, deviceId, preKeyId, preKeyPublic, signedPreKeyId, signedPreKeyPublic, signedPreKeySignature, identityKey);
      } catch (err) {
        console.log('ERROR -- Unable to create PreKeyBundle');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }
  }

  export class Curve implements CurveDef {
    static generateKeyPair(): TypeDef.ECKeyPair {
      try {
        return new org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
      } catch (err) {
        console.log('ERROR -- Unable to generate KeyPair');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    static calculateSignature(signingKey: TypeDef.ECPrivateKey, message: any): any {
      try {
        return new org.whispersystems.libsignal.ecc.Curve.calculateSignature(signingKey, message);
      } catch (err) {
        console.log('ERROR -- Unable to calculate signature');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }
  }

  export class KeyHelper implements KeyHelperDef {

    public static generateRegistrationId(extendedRange?: boolean): number {
      if (typeof extendedRange === 'undefined') extendedRange = false;
      return org.whispersystems.libsignal.util.KeyHelper.generateRegistrationId(extendedRange);
    }
  
    public static generateIdentityKeyPair(): any {
      try {
        return org.whispersystems.libsignal.util.KeyHelper.generateIdentityKeyPair();
      } catch (err) {
        console.log('ERROR -- Unable to generate IdentityKeyPair');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    public static generateIdentityKeyPairFormatted(): any {
      try {
        let IDKeyPair = org.whispersystems.libsignal.util.KeyHelper.generateIdentityKeyPair();
        return {
          pubKey: Util.base64Encode(IDKeyPair.getPublicKey().serialize()),
          privKey: Util.base64Encode(IDKeyPair.getPrivateKey().serialize()),
        }
      } catch (err) {
        console.log('ERROR -- Unable to generate IdentityKeyPairFormatted');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }
  
    public static generateKeyPair(pubKey: any, privKey: any): TypeDef.ECKeyPair {
      return new org.whispersystems.libsignal.ecc.ECKeyPair(pubKey, privKey);
    }
    
    public static importIdentityKeyPair(serialized: any): TypeDef.IdentityKeyPair {
      return new org.whispersystems.libsignal.IdentityKeyPair(serialized);
    }
  
    public static importSignedPreKeyRecord(serialized: any): TypeDef.SignedPreKeyRecord {
      return new org.whispersystems.libsignal.state.SignedPreKeyRecord(serialized);
    }

    public static importSignalProtocolAddress(name: any, deviceId: number): TypeDef.SignalProtocolAddress {
      return new org.whispersystems.libsignal.SignalProtocolAddress(name, deviceId);
    }
  
    public static generatePreKeys(start: number, count: number): TypeDef.PreKeyRecord[] {
      try {
        return org.whispersystems.libsignal.util.KeyHelper.generatePreKeys(start, count);
      } catch (err) {
        console.log('ERROR -- Unable to generate PreKeyBundle');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    public static generatePreKeysFormatted(start: number, count: number): any[] {
      try {
        let result = [];
        let preKeys: any = org.whispersystems.libsignal.util.KeyHelper.generatePreKeys(start, count);
        for (let i=0; i < preKeys.size(); i++) {
          let key: TypeDef.PreKeyRecord = preKeys.get(i);
          let keyPair: TypeDef.ECKeyPair = key.getKeyPair();
          result.push({
            keyId: key.getId(),
            keyPair: {
              pubKey: Util.base64Encode(keyPair.getPublicKey().serialize()),
              privKey: Util.base64Encode(keyPair.getPrivateKey().serialize())
            },
            serialized: Util.base64Encode(key.serialize())
          });
        }

        return result;
      } catch (err) {
        console.log('ERROR -- Unable to generate PreKeyBundleFormatted');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    public static generateLastResortPreKeyRecord(): TypeDef.PreKeyRecord {
      let keyPair: TypeDef.ECKeyPair = Curve.generateKeyPair();
      return new org.whispersystems.libsignal.state.PreKeyRecord(0xFFFFFF, keyPair);
    }
  
    public static generateSignedPreKey(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number): any {
      try {
        return org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
      } catch (err) {
        console.log('ERROR -- Unable to generate SignedPreKey');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }

    public static generateSignedPreKeyFormatted(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number): any {
      try {
        let signedPreKey: TypeDef.SignedPreKeyRecord = org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);

        return {
          keyId: signedPreKey.getId(),
          keyPair: {
            pubKey: Util.base64Encode(signedPreKey.getKeyPair().getPublicKey().serialize()),
            privKey: Util.base64Encode(signedPreKey.getKeyPair().getPrivateKey().serialize()),
          },
          signature: Util.base64Encode(signedPreKey.getSignature())
        };
      } catch (err) {
        console.log('ERROR -- Unable to generate SignedPreKey');
        console.log(err.message ? err.message : '...');
      }
      return null;
    }
  
    public static verifySignedPreKey(signingKey: TypeDef.ECPublicKey, message: any, signature: any): boolean {
      return org.whispersystems.libsignal.ecc.Curve.verifySignature(signingKey, message, signature);
    }
  }

  export class ClientInfo implements ClientInfoDef {
    private identityKey: TypeDef.IdentityKey;
    private registrationId: number;
    private deviceId: number;
    private preKeys: any[];
    private signedPreKeyId: number;
    private signedPreKey: TypeDef.ECPublicKey;
    private signedPreKeySignature; //byte[]

    constructor(identityKey: TypeDef.IdentityKey, registrationId: number, deviceId: number, preKeys: any[], signedPreKeyId: number, signedPreKey: TypeDef.ECPublicKey, signedPreKeySignature: any) {
      this.identityKey = identityKey;
      this.registrationId = registrationId;
      this.deviceId = deviceId;
      this.preKeys = preKeys;
      this.signedPreKeyId = signedPreKeyId;
      this.signedPreKey = signedPreKey;
      this.signedPreKeySignature = signedPreKeySignature;
    }

    private fetchPreKey(preKeyIndex) {
      let preKey = this.preKeys.splice(preKeyIndex, 1);
      return preKey[0];
    }

    public getPreKeyBundle() {
      let random        = new java.util.Random();
      let preKeyIds     = Object.keys(this.preKeys);
      let preKeyIndex   = preKeyIds[random.nextInt(preKeyIds.length)];
      let preKey        = this.fetchPreKey(preKeyIndex);

      return {
        registrationId: this.registrationId,
        deviceId: this.deviceId,
        preKeyPublic: preKey.pubKey,
        preKeyRecordId: preKey.id,
        signedPreKeyPublic: this.signedPreKey,
        signedPreKeyRecordId: this.signedPreKeyId,
        signature: this.signedPreKeySignature,
        identityPubKey: this.identityKey
      }
    }
  }

  export class Client implements ClientDef {
    private random: java.util.Random;
    private address: TypeDef.SignalProtocolAddress;
    public store: ISignalProtocolStore;
    
    private preKeys: any[];
    private signedPreKey: any;
    private contacts: any[];
    private identityKeyPair: TypeDef.IdentityKeyPair;

    public registrationId: number;
    public username: string;
    public deviceId: number;
    
    constructor(clientName: string, registrationId: number, deviceId: number, identityKeyPairStr?: string, signedPreKeyStr?: string, importedPreKeys?: any[], contacts?: any[]) {
      
      this.username       = clientName;
      this.deviceId       = deviceId;
      this.registrationId = registrationId;

      this.random   = new java.util.Random();
      this.contacts = [];
      this.preKeys  = [];
      this.identityKeyPair;
      this.signedPreKey;

      this.createAddress();
      this.createIdentityKeyPair(identityKeyPairStr);
      this.createSignedPreKey(signedPreKeyStr);

      // create the in-memory storage for signal session
      this.store = Core.createMemorySignalProtocolStore(this.identityKeyPair, this.registrationId);

      // store the signed prekey record
      this.store.storeSignedPreKey(this.signedPreKey.getId(), this.signedPreKey);

      // generate a "last resort" prekey record
      let lastResortPreKeyRecord = KeyHelper.generateLastResortPreKeyRecord();
      this.store.storePreKey(lastResortPreKeyRecord.getId(), lastResortPreKeyRecord);

      this.createPreKeys(importedPreKeys);
      this.createContacts(contacts);
    }

    public hasContact(contactName: string): boolean {
      let contactIndex = this.contacts.findIndex((contact) => {
        return !!(contact.name === contactName);
      });

      return !!(contactIndex >= 0);
    }

    public getContact(contactName: string): any {
      return this.contacts.find((contact) => {
        return !!(contact.name === contactName);
      });
    }

    public getContactIndex(contactName: string): any {
      return this.contacts.findIndex((contact) => {
        return !!(contact.name === contactName);
      });
    }

    public getSessionRecord(contactName: string): any {
      if (!this.hasContact(contactName)) return false;
      
      let contact = this.getContact(contactName);
      return this.store.loadSession(contact.signalAddress);
    }

    public hasSession(contactName: string): boolean {
      if (!this.hasContact(contactName)) return false;
      
      let contact = this.getContact(contactName);
      return !!(this.store.containsSession(contact.signalAddress));
    }

    public hasPreKey(preKeyId: number): boolean {
      return !!(this.store.containsPreKey(preKeyId));
    }

    public hasSignedPreKey(signedPreKeyId: number): boolean {
      return !!(this.store.containsSignedPreKey(signedPreKeyId));
    }

    public generatePreKeyBatch(startFrom?: number): any[] {
      if (typeof startFrom === 'undefined') startFrom = this.random.nextInt(0xFFFFFF-101);
      
      let preKeys = KeyHelper.generatePreKeysFormatted(startFrom, 100);
      preKeys.forEach((preKey) => {
        try {
          this.preKeys.push({
            id: preKey.keyId,
            pubKey: preKey.keyPair.pubKey,
            serialized: preKey.serialized
          });

          let preKeyRecord = Core.importPreKeyRecord(Util.base64Decode(preKey.serialized));
          this.store.storePreKey(preKeyRecord.getId(), preKeyRecord);
        } catch (err) {
          console.log('Unable to import prekey batch');
          console.log(err);
        }
      });

      return preKeys.map((preKey) => {
        return {
          id: preKey.keyId,
          pubKey: preKey.keyPair.pubKey,
          serialized: preKey.serialized
        }
      });
    }

    public async importPreKeys(preKeys: any[]): Promise<boolean> {
      if (typeof preKeys === 'undefined') {
        console.log('No prekeys provided to import!');
        return false;
      }

      preKeys.forEach((_key) => {
        let preKeyRecord: TypeDef.PreKeyRecord = Core.importPreKeyRecord(Util.base64Decode(_key.serialized));
        let keyPair: TypeDef.ECKeyPair = preKeyRecord.getKeyPair();

        this.preKeys.push({
          id: preKeyRecord.getId(),
          pubKey: Util.base64Encode(keyPair.getPublicKey().serialize()),
          serialized: Util.base64Encode(preKeyRecord.serialize())
        });

        this.store.storePreKey(preKeyRecord.getId(), preKeyRecord);
      });

      return true;
    }

    public exportRegistrationObj() {
      return {
        address: {
          name: this.address.getName(),
          deviceId: this.address.getDeviceId(),
          registrationId: this.store.getLocalRegistrationId()
        },
        identityPubKey: Util.base64Encode(this.store.getIdentityKeyPair().getPublicKey().serialize()),
        signedPreKey: {
          id: this.signedPreKey.getId(),
          pubKey: Util.base64Encode(this.signedPreKey.getKeyPair().getPublicKey().serialize()),
          signature: Util.base64Encode(this.signedPreKey.getSignature())
        },
        preKeys: this.preKeys.map((key) => {
          return {
            id: key.id,
            pubKey: key.pubKey
          }
        })
      }
    }

    public addSession(contact: any, contactBundle: any): Promise<boolean> {
      try {
        // console.log(`>> Adding Session [${contact.name}][${contact.deviceId}][${contact.registrationId}] to Address:[${this.address.getName()}]`);

        // recreate SignalProtocolAddress
        let signalAddress = Core.createSignalProtocolAddress(contact.registrationId, contact.deviceId);

        // recreate PreKeyBundle
        let preKeyBundle = this.importPreKeyBundle(signalAddress, contactBundle);

        // create SessionBuilder
        let sessionBuilder = Core.createSessionBuilder(this.store, signalAddress);

        // import the PreKeyBundle into the SessionBuilder
        // ...store.identityKeyStore.saveIdentity(remoteAddress, preKey.getIdentityKey());
        // ...store.sessionStore.storeSession(remoteAddress, sessionRecord);
        sessionBuilder.process(preKeyBundle);

        // create SessionCipher
        let sessionCipher = Core.createSessionCipher(this.store, signalAddress);

        if (this.hasContact(contact.name)) {
          console.log('updating contact');
          let nContact = this.getContactIndex(contact.name);
          this.contacts[nContact].sessionCipher = sessionCipher;
        } else {
          console.log('creating contact');
          this.contacts.push({
            name: contact.name,
            registrationId: contact.registrationId,
            deviceId: contact.deviceId,
            preKeyBundle: contactBundle,
            sessionCipher: sessionCipher,
            signalAddress: signalAddress
          });
        }

        return Promise.resolve(true);
      } catch(err) {
        console.log(`Unable to add session for [${contact.name}]`);
        console.log(err.message ? err.message : err);
        throw new Error('bad_session');
      }
    }

    public prepareMessage(contactName: string, message: string): Promise<string> {
      if (!this.hasContact(contactName)) {
        throw new Error('missing_contact');
      }

      let cipher = this.getContact(contactName).sessionCipher;
      return Promise.resolve(this.encryptMessage(message, cipher));
    }

    public encodeMessage(message: string): Promise<string> {
      return Promise.resolve(Util.base64Encode(message));
    }

    public decodeMessage(message: string): Promise<any> {
      return Promise.resolve(Util.base64Decode(message));
    }

    public async decryptEncodedMessage(contactName: string, message: string) {
      if (!this.hasContact(contactName)) {
        throw new Error('missing_contact');
      }

      let decodedMessage = await this.decodeMessage(message);
      let cipher = this.getContact(contactName).sessionCipher;
      return Promise.resolve(this.decryptMessage(decodedMessage, cipher));
    }

    public toJSON(): any {
      return {
        username: this.username,
        deviceId: this.deviceId,
        registrationId: this.registrationId,
        address: {
          name: this.registrationId,
          deviceId: this.deviceId
        },
        identityKeyPair: Util.base64Encode(this.store.getIdentityKeyPair().serialize()),
        signedPreKey: Util.base64Encode(this.signedPreKey.serialize()),
        contacts: this.contacts.map((c) => {
          return {
            "address": {
              "name": c.name,
              "registrationId": c.registrationId,
              "deviceId": c.deviceId,
            },
            "preKeyBundle": {
              "registrationId": c.preKeyBundle.registrationId,
              "deviceId": c.preKeyBundle.deviceId,
              "preKeyPublic": c.preKeyBundle.preKeyPublic,
              "preKeyRecordId": c.preKeyBundle.preKeyRecordId,
              "signedPreKeyPublic": c.preKeyBundle.signedPreKeyPublic,
              "signedPreKeyRecordId": c.preKeyBundle.signedPreKeyRecordId,
              "signature": c.preKeyBundle.signature,
              "identityPubKey": c.preKeyBundle.identityPubKey
            }
          };
        }),
        preKeys: this.preKeys
      }
    }

    public serialize(): any {
      let serialize = {
        client: {
          registrationId: this.registrationId,
          username: this.username,
          deviceId: this.deviceId
        },
        contacts: this.contacts,
        signedPreKey: Util.base64Encode(this.signedPreKey.serialize()),
        identityKeyPair: Util.base64Encode(this.store.getIdentityKeyPair().serialize()),
        preKeys: this.preKeys
      };

      return JSON.stringify(serialize);
    }

    private importPreKeyBundle(signalAddress: any, importedData: any): PreKeyBundleDef {
      let identityPubKey = Core.importIdentityKey(Util.base64Decode(importedData.identityPubKey));

      return Core.createPreKeyBundle(
        Number(signalAddress.getName()),
        Number(signalAddress.getDeviceId()),
        importedData.preKeyRecordId,
        Core.importPublicKey(Util.base64Decode(importedData.preKeyPublic)),
        importedData.signedPreKeyRecordId,
        Core.importPublicKey(Util.base64Decode(importedData.signedPreKeyPublic)),
        Util.base64Decode(importedData.signature),
        identityPubKey
      );
    }

    private encryptMessage(message: string, sessionCipher: any): any {
      let javaStr = new java.lang.String(message);
      return sessionCipher.encrypt(javaStr.getBytes("UTF-8")).serialize();
    }

    private decryptMessage(message: any, cipher: any) {
      let signalMessage;

      try {
        signalMessage = Core.createPreKeySignalMessage(message);
        if (signalMessage) {
          console.log('isPreKeySignalMessage');
          let text = cipher.decrypt(signalMessage);
          return new java.lang.String(text).toString();
        } else {
          console.log('Failed PreKeySignalMessage will try SignalMessage');
          signalMessage = Core.createSignalMessage(message);

          let text = cipher.decrypt(signalMessage);
          return new java.lang.String(text).toString();
        }
      } catch (err) {
        console.log('Unable to decrypt[1]');
        console.log(err);
      }

      return new Error('Unable to decrypt[2]');
    }

    /**
     * create a signal protocol address identifier
     */
    private createAddress() {
      this.address = Core.createSignalProtocolAddress(this.username, this.deviceId);

      return this.address;
    }

    /**
     * generate or import an identity key pair
     * 
     * @param importedIdentityKeyPair An optional Base64 encoded IdentityKeyPair
     * that was previously serialized.
     */
    private createIdentityKeyPair(importedIdentityKeyPair?: string) {
      if (typeof importedIdentityKeyPair === 'undefined') {
        this.identityKeyPair = KeyHelper.generateIdentityKeyPair();
      } else {
        this.identityKeyPair = Core.importIdentityKeyPair(Util.base64Decode(importedIdentityKeyPair));
      }

      return this.identityKeyPair;
    }

    /**
     * generate or import a signed prekey record
     * 
     * @param importedSignedPreKey An optional Base64 encoded SignedPreKeyRecord that was
     * previously serialized.
     */
    private createSignedPreKey(importedSignedPreKey: string) {
      if (typeof importedSignedPreKey === 'undefined') {
        this.signedPreKey = KeyHelper.generateSignedPreKey(this.identityKeyPair, this.random.nextInt(0xFFFFFF-1));
      } else {
        this.signedPreKey = Core.importSignedPreKeyRecord(Util.base64Decode(importedSignedPreKey));
      }

      return this.signedPreKey;
    }

    /**
     * generate or import an array of unsigned prekey records
     * - adds them to private array of prekey records (for export)
     * - adds them to private array of prekey serialized records (for storage/import)
     * - adds them to in-memory storage
     * 
     * @param importedPreKeys An optional array of pre-formatted PreKeyRecords to use instead of
     * generating a new recordset
     */
    private createPreKeys(importedPreKeys: any[]) {
      if (typeof importedPreKeys === 'undefined') {
        let preKeys = KeyHelper.generatePreKeysFormatted(this.random.nextInt(0xFFFFFF-101), 100);
        preKeys.forEach((preKeyFormatted) => {
          try {
            this.preKeys.push({
              id: preKeyFormatted.keyId,
              pubKey: preKeyFormatted.keyPair.pubKey,
              serialized: preKeyFormatted.serialized
            });

            let preKeyRecord = Core.importPreKeyRecord(Util.base64Decode(preKeyFormatted.serialized));
            this.store.storePreKey(preKeyRecord.getId(), preKeyRecord);
          } catch (err) {
            console.log('nope2');
            console.log(err);
          }
        });
      } else {
        importedPreKeys.forEach((preKey) => {
          let preKeyRecord = Core.importPreKeyRecord(Util.base64Decode(preKey.serialized));
          let keyPair: TypeDef.ECKeyPair = preKeyRecord.getKeyPair();

          this.preKeys.push({
            id: preKeyRecord.getId(),
            pubKey: Util.base64Encode(keyPair.getPublicKey().serialize()),
            serialized: Util.base64Encode(preKeyRecord.serialize())
          });

          this.store.storePreKey(preKeyRecord.getId(), preKeyRecord);
        });
      }

      return this.preKeys;
    }

    /**
     * Imports an array of clients previously saved by creating a new session based on the
     * contacts saved details.
     * 
     * @param importedContacts An optional array of formatted contacts that should be imported
     * upon Client creation.
     */
    private createContacts(importedContacts: any[]) {
      if (typeof importedContacts !== 'undefined' && importedContacts.length > 0) {
        importedContacts.forEach(async (contact) => {
          await this.addSession(contact.address, contact.preKeyBundle);
          console.log(`...added ${contact.address.name} for ${this.username}`, {
            hasContact: this.hasContact(contact.address.name),
            hasSession: this.hasSession(contact.address.name)
          });
        });
      }

      return this.contacts;
    }
  }
}


