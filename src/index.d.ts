import {
  KeyHelperDef,
  UtilDef,
  MemorySignalProtocolStoreDef,
  InMemorySignalProtocolStoreDef,
  TypeDef,
  SignedPreKeyStoreDef,
  PreKeyStoreDef,
  SessionStoreDef,
  IdentityKeyStoreDef,
  ISignalProtocolStore,
  SessionBuilderDef,
  SessionCipherDef,
  PreKeyBundleDef,
  TestCoreDef,
  CoreDef } from './libsignal-protocol.common';

/**
 * @file org.whispersystems:signal-protocol-android
 * @author https://github.com/signalapp
 * @module org.whispersystems:signal-protocol-android
 * @license GPL-3.0
 * 
 * Source:  https://github.com/signalapp/libsignal-protocol-java
 * License: https://github.com/signalapp/libsignal-protocol-java/blob/master/LICENSE
 */
export namespace LibsignalProtocol {

  export namespace Type {

    export class CiphertextMessage {
      CURRENT_VERSION: number;
      WHISPER_TYPE: number;
      PREKEY_TYPE: number;
      SENDERKEY_TYPE: number;
      SENDERKEY_DISTRIBUTION_TYPE: number;
      ENCRYPTED_MESSAGE_OVERHEAD: number;

      serialize(): any; //byte[]
      getType(): number;
    }

    export class PreKeySignalMessage extends CiphertextMessage {
      getMessageVersion(): number;
      getIdentityKey(): IdentityKey;
      getRegistrationId(): number;
      getPreKeyId(): any;
      getSignedPreKeyId(): any;
      getBaseKey(): ECPublicKey;
      getWhisperMessage(): SignalMessage;
      serialize(): any;
      getType(): any;
  
      constructor(serialized: any);
      constructor(messageVersion: number, registrationId: number, preKeyId: any, signedPreKeyId: number, baseKey: ECPublicKey, identityKey: IdentityKey);
    }
  
    export class SignalMessage {
      getSenderRatchetKey(): ECPublicKey;
      getMessageVersion(): number;
      getCounter(): number;
      getBody(): any;
      verifyMac(senderIdentityKey: IdentityKey, receiverIdentityKey: IdentityKey, macKey: any): void;
      serialize(): any;
      getType(): any;
      isLegacy(message: any): boolean;
  
      constructor(serialized: any);
      constructor(messageVersion: number, macKey: any, senderRatchetKey: ECPublicKey, counter: number, previousCounter: number, ciphertext: any, senderIdentityKey: IdentityKey, receiverIdentityKey: IdentityKey);
    }

    export class ECPrivateKey {
      getType(): number;
      serialize(): any; //byte[]
    }

    export class ECPublicKey {
      KEY_SIZE: number; // 33
    
      getType(): number;
      serialize(): any; //byte[]
    }
    
    export class ECKeyPair {
      getPublicKey(): ECPublicKey;
      getPrivateKey(): ECPrivateKey;
    
      constructor(publicKey: ECPublicKey, privateKey: ECPrivateKey);
    }

    export class Curve {
      public static verifySignature(signingKey: ECPublicKey, message: any[], signature: any[]): boolean;
    }

    export class PreKeyRecord {
      getId(): number;
      getKeyPair(): ECKeyPair;
      serialize(): any; //byte[]
    
      constructor(id: number, keyPair: ECKeyPair);
    }

    export class SignedPreKeyRecord {
      getId(): number;
      getKeyPair(): ECKeyPair;
      serialize(): any; //byte[]
      getSignature(): any; //byte[]

      constructor(id: number, timestamp: number, keyPair: ECKeyPair, signature: any);
      constructor(serialized: any[]);
    }

    export class IdentityKey {
      getPublicKey(): ECPublicKey;
      serialize(): any; //byte[]
      hashCode(): number;
    
      constructor(publicKey: ECPublicKey);
    }
  
    /**
     * Holder for public and private identity key pair.
     *
     * @author Moxie Marlinspike
     */
    export class IdentityKeyPair {
      getPublicKey(): IdentityKey;
      getPrivateKey(): ECPrivateKey;
      serialize(): any; //byte[]
    
      constructor(publicKey: IdentityKey, privateKey: ECPrivateKey);
      constructor(serialized: any[]);
    }

    export class SignalProtocolAddress {
      getName(): string;
      getDeviceId(): number;
      toString(): string;
      equals(other: any): boolean;
    
      constructor(name: string, deviceId: number);
    }
  }

  export class Core implements CoreDef {
    static importPreKeyRecord(serialized: any[]): TypeDef.PreKeyRecord;
    static importSignedPreKey(serialized: any[]): TypeDef.SignedPreKeyRecord;
    static createPreKeyRecord(id: number, keyPair: TypeDef.ECKeyPair): TypeDef.PreKeyRecord;
    static createSignedPreKeyRecord(id: number, timestamp: number, keyPair: TypeDef.ECKeyPair, signature: any): TypeDef.SignedPreKeyRecord;
    static createSignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): MemorySignalProtocolStoreDef;
    static createTestSignalProtocolStore(): ISignalProtocolStore;
    static createIdentityKeyPair(publicKey: TypeDef.IdentityKey, privateKey: TypeDef.ECPrivateKey): TypeDef.IdentityKeyPair;
    static createIdentityKey(publicKey: TypeDef.ECPublicKey): TypeDef.IdentityKey;
    static createSessionBuilder(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionBuilderDef;
    static createSessionCipher(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionCipherDef;
    static createMemorySignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): InMemorySignalProtocolStoreDef;
    static createSessionRecord(): TypeDef.SessionRecord;
    static createSignalProtocolAddress(registrationId: number, deviceId: number): TypeDef.SignalProtocolAddress;
    static createCiphertextMessage(): TypeDef.CiphertextMessage;
    static createPreKeyBundle(registrationId: number, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any[], identityKey: TypeDef.IdentityKey): PreKeyBundleDef;
  }

  export class KeyHelper implements KeyHelperDef {
    /**
     * Generate a registration ID.  Clients should only do this once,
     * at install time.
     *
     * @param extendedRange By default (false), the generated registration
     *                      ID is sized to require the minimal possible protobuf
     *                      encoding overhead. Specify true if the caller needs
     *                      the full range of MAX_INT at the cost of slightly
     *                      higher encoding overhead.
     * @return the generated registration ID.
     */
    static generateRegistrationId(extendedRange?: boolean): number;

    /**
     * Generate an identity key pair.  Clients should only do this once,
     * at install time.
     * 
     * @return the generated IdentityKeyPair.
     */
    static generateIdentityKeyPair(): LibsignalProtocol.Type.IdentityKeyPair;

    static importIdentityKeyPair(serialized: any): LibsignalProtocol.Type.IdentityKeyPair;
  
    static importSignedPreKeyRecord(serialized: any): LibsignalProtocol.Type.SignedPreKeyRecord;

    static importSignalProtocolAddress(name: any, deviceId: number): TypeDef.SignalProtocolAddress;
    
    /**
     * Generate a list of PreKeys.  Clients should do this at install time, and
     * subsequently any time the list of PreKeys stored on the server runs low.
     * <p>
     * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
     * store PreKeys in a circular buffer, so that they are repeated as infrequently
     * as possible.
     *
     * @param start The starting PreKey ID, inclusive.
     * @param count The number of PreKeys to generate.
     * @return the list of generated PreKeyRecords.
     */
    static generatePreKeys(start: number, count: number): LibsignalProtocol.Type.PreKeyRecord[];
  
    static generateSignedPreKey(identityKeyPair: LibsignalProtocol.Type.IdentityKeyPair, signedPreKeyId: number, raw?: boolean): any;
  
    static verifySignedPreKey(signingKey: LibsignalProtocol.Type.ECPublicKey, message: any, signature: any): boolean;

    /**
     * Generate a list of PreKeys.  Clients should do this at install time, and
     * subsequently any time the list of PreKeys stored on the server runs low.
     * <p>
     * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
     * store PreKeys in a circular buffer, so that they are repeated as infrequently
     * as possible.
     *
     * @param start The starting PreKey ID, inclusive.
     * @param count The number of PreKeys to generate.
     * @return the list of generated PreKeyRecords.
     */
    static generatePreKeys(start: number, count: number): LibsignalProtocol.Type.PreKeyRecord[];

    /**
     * Generate a signed PreKey
     *
     * @param identityKeyPair The local client's identity key pair.
     * @param signedPreKeyId The PreKey id to assign the generated signed PreKey
     *
     * @return the generated signed PreKey
     * @throws InvalidKeyException when the provided identity key is invalid
     */
    static generateSignedPreKey(identityKeyPair: LibsignalProtocol.Type.IdentityKeyPair, signedPreKeyId: number): LibsignalProtocol.Type.SignedPreKeyRecord;
  }

  export class SessionCipher implements SessionCipherDef {
    sessionStore: SessionStoreDef;
    identityKeyStore: IdentityKeyStoreDef;
    sessionBuilder: SessionBuilderDef;
    preKeyStore: PreKeyStoreDef;
    remoteAddress: TypeDef.SignalProtocolAddress;
  
    encrypt(paddedMessage: any): Type.CiphertextMessage;
    decrypt(ciphertext: any): any;
    decrypt(ciphertext: any, callback: any): any;

    constructor(store: ISignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress);
    constructor(sessionStore: SessionStoreDef, preKeyStore: PreKeyStoreDef, signedPreKeyStore: SignedPreKeyStoreDef, identityKeyStore: IdentityKeyStoreDef, remoteAddress: TypeDef.SignalProtocolAddress);
  }

  export class PreKeyBundle implements PreKeyBundleDef {
    identityKey: TypeDef.IdentityKey;
  
    getDeviceId(): number;
    getPreKeyId(): number;
    getPreKey(): TypeDef.ECPublicKey;
    getSignedPreKeyId(): number;
    getSignedPreKey(): TypeDef.ECPublicKey;
    getSignedPreKeySignature(): any[];
    getIdentityKey(): TypeDef.IdentityKey;
    getRegistrationId(): number;
  
    constructor(registrationId: number, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any[], identityKey: TypeDef.IdentityKey);
  }
  
  export class SessionBuilder implements SessionBuilderDef {
    sessionStore: SessionStoreDef;
    preKeyStore: PreKeyStoreDef;
    signedPreKeyStore: SignedPreKeyStoreDef;
    identityKeyStore: IdentityKeyStoreDef;
    remoteAddress: TypeDef.SignalProtocolAddress;

    process(sessionRecord: TypeDef.SessionRecord, message: any): any;
    process(preKey: PreKeyBundleDef): void;
    processV3(sessionRecord: TypeDef.SessionRecord, message: any): any;

    constructor(store: ISignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress);
    constructor(sessionStore: SessionStoreDef, preKeyStore: PreKeyStoreDef, signedPreKeyStore: SignedPreKeyStoreDef, identityKeyStore: IdentityKeyStoreDef, remoteAddress: TypeDef.SignalProtocolAddress);
  }

  export class TestCore implements TestCoreDef {
    BOB_ADDRESS: TypeDef.SignalProtocolAddress;
    ALICE_ADDRESS: TypeDef.SignalProtocolAddress;
  
    aliceSignedPreKey: TypeDef.ECKeyPair;
    bobSignedPreKey: TypeDef.ECKeyPair;
  
    aliceSignedPreKeyId: number;
    bobSignedPreKeyId: number;
    
    constructor();
    public testBasicSimultaneousInitiate(): void;
  }

  export class MemorySignalProtocolStore implements ISignalProtocolStore {
    Direction: any;
    getIdentityKeyPair(): TypeDef.IdentityKeyPair;
    getLocalRegistrationId(): number;
    saveIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey): boolean;
    isTrustedIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey, direction: any): boolean;
    getIdentity(address: TypeDef.SignalProtocolAddress): TypeDef.IdentityKey;
    loadPreKey(preKeyId: number): TypeDef.PreKeyRecord;
    storePreKey(preKeyId: number, record: TypeDef.PreKeyRecord): void;
    containsPreKey(preKeyId: number): boolean;
    removePreKey(preKeyId: number): void;
    loadSession(address: TypeDef.SignalProtocolAddress): TypeDef.SessionRecord;
    getSubDeviceSessions(name: string): java.util.List<java.lang.Integer>;
    storeSession(address: TypeDef.SignalProtocolAddress, record: TypeDef.SessionRecord): void;
    containsSession(address: TypeDef.SignalProtocolAddress): boolean;
    deleteSession(address: TypeDef.SignalProtocolAddress): void;
    deleteAllSessions(name: string): void;
    loadSignedPreKey(signedPreKeyId: number): TypeDef.SignedPreKeyRecord;
    loadSignedPreKeys(): TypeDef.SignedPreKeyRecord[];//java.util.List<TypeDef.SignedPreKeyRecord>;
    storeSignedPreKey(signedPreKeyId: number, record: TypeDef.SignedPreKeyRecord): void;
    containsSignedPreKey(signedPreKeyId: number): boolean;
    removeSignedPreKey(signedPreKeyId: number): void;
  
    constructor(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number);
  }

  export class InMemorySignalProtocolStore implements InMemorySignalProtocolStoreDef {
    Direction: any;
    getIdentityKeyPair(): Promise<any>;
    getLocalRegistrationId(): Promise<any>;
    put(key: string, value: any): void;
    get(key: string, defaultValue?: any): any;
    remove(key: string): void;
    isTrustedIdentity(identifier: any, identityKey, direction): Promise<any>;
    loadIdentityKey(identifier: any): Promise<any>;
    saveIdentity(identifier: any, identityKey): Promise<any>;
    loadPreKey(keyId): Promise<any>;
    storePreKey(keyId, keyPair): Promise<any>;
    removePreKey(keyId): Promise<any>;
    loadSignedPreKey(keyId): Promise<any>;
    storeSignedPreKey(keyId, keyPair): Promise<any>;
    removeSignedPreKey(keyId): Promise<any>;
    loadSession(identifier: any): Promise<any>;
    storeSession(identifier: any, record): Promise<any>;
    removeSession(identifier: any): Promise<any>;
    removeAllSessions(identifier: any): Promise<any>;
  }

  export class IdentityKeyStore implements IdentityKeyStoreDef {
    Direction: any; // SENDING, RECEIVING

    getIdentity(address: TypeDef.SignalProtocolAddress): TypeDef.IdentityKey;
    getIdentityKeyPair(): TypeDef.IdentityKeyPair;
    getLocalRegistrationId(): number;
    saveIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey): boolean;
    isTrustedIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey, direction: any): boolean;
  }

  export class SessionStore implements SessionStoreDef {
    loadSession(address: TypeDef.SignalProtocolAddress): TypeDef.SessionRecord;
    getSubDeviceSessions(name: string): java.util.List<java.lang.Integer>;
    storeSession(address: TypeDef.SignalProtocolAddress, record: TypeDef.SessionRecord): void;
    containsSession(address: TypeDef.SignalProtocolAddress): boolean;
    deleteSession(address: TypeDef.SignalProtocolAddress): void;
    deleteAllSessions(name: string): void;
  }

  export class SignedPreKeyStore implements SignedPreKeyStoreDef {
    loadSignedPreKey(signedPreKeyId: number): TypeDef.SignedPreKeyRecord;
    loadSignedPreKeys(): TypeDef.SignedPreKeyRecord[];
    storeSignedPreKey(signedPreKeyId: number, record: TypeDef.SignedPreKeyRecord): void;
    containsSignedPreKey(signedPreKeyId: number): boolean;
    removeSignedPreKey(signedPreKeyId: number): void;
  }

  export class PreKeyStore implements PreKeyStoreDef {
    loadPreKey(preKeyId: number): TypeDef.PreKeyRecord;
    storePreKey(preKeyId: number, record: TypeDef.PreKeyRecord);
    containsPreKey(preKeyId: number): boolean;
    removePreKey(preKeyId: number): boolean;
  }

  export class Util implements UtilDef {
    static base64ToArrayBuffer(base64: string): ArrayBuffer;
    static arrayBufferToBase64(buffer: Iterable<number>): string;
    static atob(str: string);
    static btoa(str: string);
    static base64Encode(mixed: any): string;
    static base64Decode(base64Str: any): number[];
    static toString(value: any): string;
    static isEqualString(value: any, compared: any): boolean;
    static rawciphertextToBinary(value: any): any;
  }
}
