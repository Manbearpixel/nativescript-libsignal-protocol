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
  TestCoreDef,
  MemorySignalProtocolStoreDef } from './libsignal-protocol.common';

import { Buffer } from 'buffer';

declare var org: any;

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

      console.log('!!! CREATED MEMORY STORE !!!');
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

      console.log('!!! CREATED CIPHER STORE !!!');
    }

    public encrypt(paddedMessage: any): any {
      return this.CipherStore.encrypt(paddedMessage);
    }

    public decrypt(ciphertext: any, callback?: any): any {
      if (typeof callback === 'undefined') return this.CipherStore.decrypt(ciphertext, callback);
      return this.CipherStore.decrypt(ciphertext);
    }
  }

  // export class SessionBuilder implements SessionBuilderDef {
  //   sessionStore: SessionStoreDef;
  //   preKeyStore: PreKeyStoreDef;
  //   signedPreKeyStore: SignedPreKeyStoreDef;
  //   identityKeyStore: IdentityKeyStoreDef;
  //   remoteAddress: TypeDef.SignalProtocolAddress;

    
    
  //   constructor(store: ISignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress) {
  //     return new org.whispersystems.libsignal.SessionBuilder(store, remoteAddress);
  //   }
  // }

  // export class PreKeyBundle implements PreKeyBundleDef {
  //   public identityKey: TypeDef.IdentityKey;
  
  //   constructor(registrationId: number, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any[], identityKey: TypeDef.IdentityKey);

  //   public getDeviceId(): number {

  //   }

  //   public getPreKeyId(): number;
  //   public getPreKey(): TypeDef.ECPublicKey;
  //   public getSignedPreKeyId(): number;
  //   public getSignedPreKey(): TypeDef.ECPublicKey;
  //   public getSignedPreKeySignature(): any[];
  //   public getIdentityKey(): TypeDef.IdentityKey;
  //   public getRegistrationId(): number;
  // }
  
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

      console.log('SAVE IDENTITY', identifier);
      
      let parts = identifier.split('.');
      let address = new org.whispersystems.libsignal.SignalProtocolAddress(parts[0], parseInt(parts[1]));

      let existing = this.get('identityKey' + address.getName());
      this.put('identityKey' + address.getName(), identityKey);

      console.log('...equal?', LibsignalProtocol.Util.isEqualString(identityKey, existing));
      if (existing && !LibsignalProtocol.Util.isEqualString(identityKey, existing)) {
        console.log('return true');
        return Promise.resolve(true);
      } else {
        console.log('return false');
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

    public static rawciphertextToBinary(value: any): any {
      return new Buffer(value, 'binary');
    }
  }

  export class TestCore implements TestCoreDef {
    BOB_ADDRESS: TypeDef.SignalProtocolAddress;
    ALICE_ADDRESS: TypeDef.SignalProtocolAddress;

    aliceSignedPreKey: TypeDef.ECKeyPair;
    bobSignedPreKey: TypeDef.ECKeyPair;

    // aliceSignedPreKeyAlt: TypeDef.SignedPreKeyRecord;
    // bobSignedPreKeyAlt: TypeDef.SignedPreKeyRecord;

    aliceSignedPreKeyId: number;
    bobSignedPreKeyId: number;

    aliceStore: ISignalProtocolStore;
    bobStore: ISignalProtocolStore;
    
    constructor() {
      this.BOB_ADDRESS    = Core.createSignalProtocolAddress(1111, 1);
      this.ALICE_ADDRESS  = Core.createSignalProtocolAddress(2222, 1);

      this.aliceStore     = Core.createTestSignalProtocolStore();
      this.bobStore       = Core.createTestSignalProtocolStore();

      this.aliceSignedPreKey  = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
      this.bobSignedPreKey    = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();

      this.aliceSignedPreKeyId  = new java.util.Random().nextInt(0xFFFFFF);//122;//this.aliceSignedPreKeyAlt.getId();
      this.bobSignedPreKeyId    = new java.util.Random().nextInt(0xFFFFFF);//111;//this.bobSignedPreKeyAlt.getId();

      // this.aliceSignedPreKeyAlt = org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(
      //   this.aliceStore.getIdentityKeyPair(), 1
      // );
      
      // this.bobSignedPreKeyAlt = org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(
      //   this.bobStore.getIdentityKeyPair(), 1
      // );

      console.log(
        'aliceReg',
        this.aliceStore.getLocalRegistrationId(),
        this.ALICE_ADDRESS.getName()
      );

      console.log('alice pub', Util.base64Encode(this.aliceStore.getIdentityKeyPair().getPrivateKey().serialize()));

      console.log(
        'bobReg',
        this.bobStore.getLocalRegistrationId(),
        this.BOB_ADDRESS.getName()
      );

      console.log('bob pub', Util.base64Encode(this.bobStore.getIdentityKeyPair().getPrivateKey().serialize()));

      // console.log(
      //   'aliceSigned',
      //   this.aliceSignedPreKeyAlt.getId(),
      //   Util.base64Encode(this.aliceSignedPreKeyAlt.getSignature())
      // );

      // console.log(
      //   'bobSigned',
      //   this.bobSignedPreKeyAlt.getId(),
      //   Util.base64Encode(this.bobSignedPreKeyAlt.getSignature())
      // );

      console.log('--- TestCore Created ---');
    }

    public testBasicSimultaneousInitiate(): void {
      console.log('--- TestCore::Running ---');
      // let aliceStore = Core.createTestSignalProtocolStore();
      // let bobStore = Core.createTestSignalProtocolStore();
      console.log('--- TestCore::Stores Created ---');
      let alicePreKeyBundle = this.createAlicePreKeyBundle(this.aliceStore);
      let bobPreKeyBundle = this.createBobPreKeyBundle(this.bobStore);
      console.log('--- TestCore::Bundles Created ---');
      let aliceSessionBuilder = Core.createSessionBuilder(this.aliceStore, this.BOB_ADDRESS);
      let bobSessionBuilder   = Core.createSessionBuilder(this.bobStore, this.ALICE_ADDRESS);
      console.log('--- TestCore::Sessions Built ---');
      let aliceSessionCipher = Core.createSessionCipher(this.aliceStore, this.BOB_ADDRESS);
      let bobSessionCipher = Core.createSessionCipher(this.bobStore, this.ALICE_ADDRESS);
      console.log('--- TestCore::Ciphers Created ---');
      aliceSessionBuilder.process(bobPreKeyBundle);
      bobSessionBuilder.process(alicePreKeyBundle);
      console.log('--- TestCore::Sessions Exchanged ---');

      let bobMessage = new java.lang.String("hey there");
      let aliceMessage = new java.lang.String("sample message");
      // let message = sessionCipher.encrypt(foo.getBytes("UTF-8"));

      let messageForBob: TypeDef.CiphertextMessage   = aliceSessionCipher.encrypt(bobMessage.getBytes("UTF-8"));
      let messageForAlice: TypeDef.CiphertextMessage = bobSessionCipher.encrypt(aliceMessage.getBytes("UTF-8"));

      console.log('--- TestCore::Encrypted ---');

      console.log({
        who: 'bob',
        msg: bobMessage.toString(),
        encrypted: Util.base64Encode(messageForBob.serialize())
      });

      console.log({
        who: 'alice',
        msg: aliceMessage.toString(),
        encrypted: Util.base64Encode(messageForAlice.serialize())
      });

      let alicePreKeySignalMessage: TypeDef.PreKeySignalMessage = Core.createPreKeySignalMessage(messageForAlice.serialize());

      // console.dir({
      //   version: alicePreKeySignalMessage.getMessageVersion(),
      //   identityPub: Util.base64Encode(alicePreKeySignalMessage.getIdentityKey().getPublicKey().serialize()),
      //   preKeyId: alicePreKeySignalMessage.getPreKeyId(),
      //   signedPreKeyId: alicePreKeySignalMessage.getSignedPreKeyId(),
      //   baseKey: alicePreKeySignalMessage.getBaseKey()
      // });

      let alicePlaintext = aliceSessionCipher.decrypt(alicePreKeySignalMessage);

      let bobPlaintext   = bobSessionCipher.decrypt(
        Core.createPreKeySignalMessage(messageForBob.serialize())
      );

      console.log('--- TestCore::Decryption ---');

      console.log({
        who: 'bob',
        msg: bobMessage.toString(),
        encrypted: Util.base64Encode(messageForBob.serialize()),
        decrypted: new java.lang.String(bobPlaintext).toString(),
        matched: new java.lang.String(alicePlaintext).equals("sample message")
      });
      
      console.log({
        who: 'alice',
        msg: aliceMessage.toString(),
        encrypted: Util.base64Encode(messageForAlice.serialize()),
        decrypted: new java.lang.String(alicePlaintext).toString(),
        matches: new java.lang.String(bobPlaintext).equals("hey there")
      });
    }

    private createAlicePreKeyBundle(aliceStore: MemorySignalProtocolStoreDef): PreKeyBundleDef {
      let aliceUnsignedPreKey: TypeDef.ECKeyPair = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
      let aliceUnsignedPreKeyId: number = new java.util.Random().nextInt(0xFFFFFF);
      // let aliceSignature: any = this.aliceSignedPreKeyAlt.getSignature();
      let aliceSignature: any = org.whispersystems.libsignal.ecc.Curve.calculateSignature(
        aliceStore.getIdentityKeyPair().getPrivateKey(),
        this.aliceSignedPreKey.getPublicKey().serialize()
      );
  
      let alicePreKeyBundle: PreKeyBundleDef = Core.createPreKeyBundle(
        Number(this.ALICE_ADDRESS.getName()), this.ALICE_ADDRESS.getDeviceId(),
        // 1, 1,
        aliceUnsignedPreKeyId,
        aliceUnsignedPreKey.getPublicKey(),
        this.aliceSignedPreKeyId,
        this.aliceSignedPreKey.getPublicKey(),
        aliceSignature,
        aliceStore.getIdentityKeyPair().getPublicKey()
      );

      aliceStore.storeSignedPreKey(this.aliceSignedPreKeyId, Core.createSignedPreKeyRecord(
        this.aliceSignedPreKeyId, java.lang.System.currentTimeMillis(), this.aliceSignedPreKey, aliceSignature
      ));
      aliceStore.storePreKey(aliceUnsignedPreKeyId, Core.createPreKeyRecord(
        aliceUnsignedPreKeyId, aliceUnsignedPreKey
      ));
  
      return alicePreKeyBundle;
    }

    private createBobPreKeyBundle(bobStore: MemorySignalProtocolStoreDef): PreKeyBundleDef {
      let bobUnsignedPreKey: TypeDef.ECKeyPair = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
      let bobUnsignedPreKeyId: number = new java.util.Random().nextInt(0xFFFFFF);
      // let bobSignature: any = this.bobSignedPreKeyAlt.getSignature();
      let bobSignature: any = org.whispersystems.libsignal.ecc.Curve.calculateSignature(
        bobStore.getIdentityKeyPair().getPrivateKey(),
        this.bobSignedPreKey.getPublicKey().serialize()
      );
  
      let bobPreKeyBundle: PreKeyBundleDef = Core.createPreKeyBundle(
        Number(this.BOB_ADDRESS.getName()), this.BOB_ADDRESS.getDeviceId(),
        // 1, 1,
        bobUnsignedPreKeyId,
        bobUnsignedPreKey.getPublicKey(),
        this.bobSignedPreKeyId,
        this.bobSignedPreKey.getPublicKey(),
        bobSignature,
        bobStore.getIdentityKeyPair().getPublicKey()
      );

      bobStore.storeSignedPreKey(this.bobSignedPreKeyId, Core.createSignedPreKeyRecord(
        this.bobSignedPreKeyId, java.lang.System.currentTimeMillis(), this.bobSignedPreKey, bobSignature
      ));
      bobStore.storePreKey(bobUnsignedPreKeyId, Core.createPreKeyRecord(
        bobUnsignedPreKeyId, bobUnsignedPreKey
      ));
  
      return bobPreKeyBundle;
    }
  }

  export class Core implements CoreDef {
    static importPreKeyRecord(serialized: any): TypeDef.PreKeyRecord {
      return new org.whispersystems.libsignal.state.PreKeyRecord(serialized);
    }

    static importSignedPreKey(serialized: any): TypeDef.SignedPreKeyRecord {
      return new org.whispersystems.libsignal.state.SignedPreKeyRecord(serialized);
    }

    static createPreKeySignalMessage(serialized: any): TypeDef.PreKeySignalMessage {
      return new org.whispersystems.libsignal.protocol.PreKeySignalMessage(serialized);
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
        let keyPair: TypeDef.ECKeyPair = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
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
      console.log('creating session builder');
      return new org.whispersystems.libsignal.SessionBuilder(store, address);
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

    static createSignalProtocolAddress(registrationId: number, deviceId: number): TypeDef.SignalProtocolAddress {
      return new org.whispersystems.libsignal.SignalProtocolAddress(registrationId + '', deviceId);
    }

    static createPreKeyBundle(registrationId: number, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any[], identityKey: TypeDef.IdentityKey): PreKeyBundleDef {
      return new org.whispersystems.libsignal.state.PreKeyBundle(registrationId, deviceId, preKeyId, preKeyPublic, signedPreKeyId, signedPreKeyPublic, signedPreKeySignature, identityKey);
    }
  }

  export class KeyHelper implements KeyHelperDef {

    public static generateRegistrationId(extendedRange?: boolean): number {
      if (typeof extendedRange === 'undefined') extendedRange = false;
      return org.whispersystems.libsignal.util.KeyHelper.generateRegistrationId(extendedRange);
    }
  
    public static generateIdentityKeyPair(): any {
      let keyPair: TypeDef.IdentityKeyPair = org.whispersystems.libsignal.util.KeyHelper.generateIdentityKeyPair();
  
      return keyPair;
  
      // return {
      //   pubKey: arrayBufferToBase64(keyPair.getPublicKey().serialize()),
      //   privKey: arrayBufferToBase64(keyPair.getPrivateKey().serialize())
      // }
  
      // let keyPair = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
      // let publicKey = new org.whispersystems.libsignal.IdentityKey(keyPair.getPublicKey());
      // return {
      //   publicKey: publicKey.serialize(),
      //   privateKey: keyPair.getPrivateKey().serialize()
      // };
      // return org.whispersystems.libsignal.util.KeyHelper.generateIdentityKeyPair();
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
      let result = [];
      // List<PreKeyRecord>
      let keys: any = org.whispersystems.libsignal.util.KeyHelper.generatePreKeys(start, count);
      
      // return keys;
  
      for (let i=0; i < keys.size(); i++) {
        let key: TypeDef.PreKeyRecord = keys.get(i);
        let keyPair: TypeDef.ECKeyPair = key.getKeyPair();
        result.push({
          keyId: key.getId(),
          keyPair: {
            pubKey: Util.arrayBufferToBase64(keyPair.getPublicKey().serialize()),
            privKey: Util.arrayBufferToBase64(keyPair.getPrivateKey().serialize())
          },
          serialized: Util.base64Encode(key.serialize())
        });
      }
  
      return result;
    }
  
    public static generateSignedPreKey(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number, raw?: boolean): any {
      let signedPreKey: TypeDef.SignedPreKeyRecord = org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
  
      if (raw) {
        // let verify = org.whispersystems.libsignal.ecc.Curve.verifySignature(identityKeyPair.getPublicKey(), signedPreKey.getKeyPair().getPublicKey(), signedPreKey.getSignature());
        // console.log('verfied?', verify);
        return signedPreKey;
      } else
        return {
          keyId: signedPreKey.getId(),
          keyPair: {
            pubKey: Util.arrayBufferToBase64(identityKeyPair.getPublicKey().serialize()),
            privKey: Util.arrayBufferToBase64(identityKeyPair.getPrivateKey().serialize()),
          },
          signature: Util.arrayBufferToBase64(signedPreKey.getSignature())
        };
    }
  
    public static verifySignedPreKey(signingKey: TypeDef.ECPublicKey, message: any, signature: any): boolean {
      console.log('signingKey.pub', signingKey.serialize());
      console.log('signingKey.message', message);
      console.log('signingKey.signature', signature);
      let test: boolean = org.whispersystems.libsignal.ecc.Curve.verifySignature(signingKey, message, signature);
  
      return test;
    }
    
    // public static generateSignedPreKeyRaw(identityKeyPair: IdentityKeyPair, signedPreKeyId: number): SignedPreKeyRecord {
    //   let keyPair: ECKeyPair = org.whispersystems.libsignal.ecc.Curve.generateKeyPair();
    //   // byte[]
    //   let signature: any = org.whispersystems.curve25519.Curve25519.getInstance(org.whispersystems.curve25519.Curve25519.BEST).calculateSignature(((DjbECPrivateKey) signingKey).getPrivateKey(), message);
    //   return org.whispersystems.libsignal.util.KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
    // }
  }
}


