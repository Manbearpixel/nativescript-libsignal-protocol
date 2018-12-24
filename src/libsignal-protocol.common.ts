export namespace TypeDef {
  export declare class CiphertextMessage {
    CURRENT_VERSION: number;
    WHISPER_TYPE: number;
    PREKEY_TYPE: number;
    SENDERKEY_TYPE: number;
    SENDERKEY_DISTRIBUTION_TYPE: number;
    ENCRYPTED_MESSAGE_OVERHEAD: number;

    serialize(): any; //byte[]
    getType(): number;
  }

  export declare class PreKeySignalMessage extends CiphertextMessage {
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

  export declare class SignalMessage {
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

  export declare class ECPrivateKey {
    getType(): number;
    serialize(): any; //byte[]
  }

  export declare class ECPublicKey {
    KEY_SIZE: number; // 33
  
    getType(): number;
    serialize(): any; //byte[]
  }
  
  export declare class ECKeyPair {
    getPublicKey(): ECPublicKey;
    getPrivateKey(): ECPrivateKey;
  
    constructor(publicKey: ECPublicKey, privateKey: ECPrivateKey);
  }

  export declare class Curve {
    public static verifySignature(signingKey: ECPublicKey, message: any[], signature: any[]): boolean;
  }

  export declare class PreKeyRecord {
    getId(): number;
    getKeyPair(): ECKeyPair;
    serialize(): any; //byte[]
  
    constructor(id: number, keyPair: ECKeyPair);
  }

  export declare class SignedPreKeyRecord {
    getId(): number;
    getKeyPair(): ECKeyPair;
    serialize(): any; //byte[]
    getSignature(): any; //byte[]

    constructor(id: number, timestamp: number, keyPair: ECKeyPair, signature: any);
    constructor(serialized: any[]);
  }

  export declare class IdentityKey {
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
  export declare class IdentityKeyPair {
    getPublicKey(): IdentityKey;
    getPrivateKey(): ECPrivateKey;
    serialize(): any; //byte[]
  
    constructor(publicKey: IdentityKey, privateKey: ECPrivateKey);
    constructor(serialized: any[]);
  }

  export declare class SignalProtocolAddress {
    getName(): string;
    getDeviceId(): number;
    toString(): string;
    equals(other: any): boolean;
  
    constructor(name: string, deviceId: number);
  }

  export declare class SessionState {
    MAX_MESSAGE_KEYS: number; // 2000
    sessionStructure: any;

    getStructure(): any;
    getAliceBaseKey(): any[];
    setAliceBaseKey(aliceBaseKey: any[]);
    setSessionVersion(version: number): void;
    getSessionVersion(): number;
    setRemoteIdentityKey(identityKey: IdentityKey): void;
    setLocalIdentityKey(identityKey: IdentityKey): void;
    getRemoteIdentityKey(): IdentityKey;
    getLocalIdentityKey(): IdentityKey;
    getPreviousCounter(): number;
    getRootKey(): any;
    setRootKey(rootKey: any): void;
    getSenderRatchetKey(): ECPublicKey;
    getSenderRatchetKeyPair(): ECKeyPair;
    hasReceiverChain(senderEphemeral: ECPublicKey): boolean;
    hasSenderChain(): boolean;
    getReceiverChainKey(senderEphemeral: ECPublicKey): any;
    addReceiverChain(senderRatchetKey: ECPublicKey, chainKey: any): void;
    setSenderChain(senderRatchetKeyPair: ECKeyPair, chainKey: any): void;
    getSenderChainKey(): any;
    setSenderChainKey(nextChainKey: any): void;
    hasMessageKeys(senderEphemeral: ECPublicKey, counter: number): boolean;
    removeMessageKeys(senderEphemeral: ECPublicKey, counter: number): any;
    setMessageKeys(senderEphemeral: ECPublicKey, messageKeys: any): void;
    setReceiverChainKey(senderEphemeral: ECPublicKey, chainKey: any): void;
    setPendingKeyExchange(sequence: number, ourBaseKey: ECKeyPair, ourRatchetKey: ECKeyPair, ourIdentityKey: IdentityKey): void;
    getPendingKeyExchangeSequence(): number;
    getPendingKeyExchangeBaseKey(): ECKeyPair;
    getPendingKeyExchangeRatchetKey(): ECKeyPair;
    getPendingKeyExchangeIdentityKey(): IdentityKeyPair;
    hasPendingKeyExchange(): boolean;
    setUnacknowledgedPreKeyMessage(preKeyId: any, signedPreKeyId: number, baseKey: ECPublicKey): void;
    hasUnacknowledgedPreKeyMessage(): boolean;
    getUnacknowledgedPreKeyMessageItems(): any;
    clearUnacknowledgedPreKeyMessage(): void;
    setRemoteRegistrationId(registrationId: number): void;
    getRemoteRegistrationId(): number;
    getLocalRegistrationId(): number;
    serialize(): any[];
    
    constructor();
    constructor(sessionStructure: any);
    constructor(copy: SessionState);
  }

  /**
   * A SessionRecord encapsulates the state of an ongoing session.
   *
   * @author Moxie Marlinspike
   */
  export declare class SessionRecord {
    ARCHIVED_STATES_MAX_LENGTH: number; //40
    sessionState: SessionState;
    previousStates: java.util.LinkedList<SessionState>;
    fresh: boolean;

    hasSessionState(version: number, aliceBaseKey: any[]): boolean;
    getSessionState(): SessionState;
    getPreviousSessionStates(): java.util.List<SessionState>;
    removePreviousSessionStates(): void;
    isFresh(): boolean;
    archiveCurrentState(): void;
    promoteState(promotedState: SessionState): void;
    setState(sessionState: SessionState);
    serialize(): any[];

    constructor();
    constructor(sessionState: SessionState);
    constructor(serialized: any[]);
  }
}

export declare class CoreDef {
  static importPreKeyRecord(serialized: any[]): TypeDef.PreKeyRecord;
  static importSignedPreKeyRecord(serialized: any): TypeDef.SignedPreKeyRecord;
  static importSignedPreKey(serialized: any[]): TypeDef.SignedPreKeyRecord;
  static importIdentityKey(serialized: any[]): TypeDef.IdentityKey;
  static importPublicKey(serialized: any): TypeDef.ECPublicKey;
  static createPreKeySignalMessage(serialized: any): TypeDef.PreKeySignalMessage;
  static createPreKeyRecord(id: number, keyPair: TypeDef.ECKeyPair): TypeDef.PreKeyRecord;
  static createSignedPreKeyRecord(id: number, timestamp: number, keyPair: TypeDef.ECKeyPair, signature: any): TypeDef.SignedPreKeyRecord;
  static createSignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): MemorySignalProtocolStoreDef;
  static createTestSignalProtocolStore(): ISignalProtocolStore;
  static createIdentityKeyPair(publicKey: TypeDef.IdentityKey, privateKey: TypeDef.ECPrivateKey): TypeDef.IdentityKeyPair;
  static createIdentityKey(publicKey: TypeDef.ECPublicKey): TypeDef.IdentityKey;
  static createSessionBuilder(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionBuilderDef;
  static createSessionCipher(store: ISignalProtocolStore, address: TypeDef.SignalProtocolAddress): SessionCipherDef;
  static createMemorySignalProtocolStore(identityKeyPair: TypeDef.IdentityKeyPair, registrationId: number): MemorySignalProtocolStoreDef;
  static createSessionRecord(): TypeDef.SessionRecord;
  static createSignalProtocolAddress(registrationId: number, deviceId: number): TypeDef.SignalProtocolAddress;
  static createPreKeyBundle(registrationId: number, deviceId: number, preKeyId: number, preKeyPublic: TypeDef.ECPublicKey, signedPreKeyId: number, signedPreKeyPublic: TypeDef.ECPublicKey, signedPreKeySignature: any, identityKey: TypeDef.IdentityKey | any): PreKeyBundleDef;
}

export declare class CurveDef {
  static generateKeyPair(): TypeDef.ECKeyPair;
  static calculateSignature(signingKey: TypeDef.ECPrivateKey, message: any): any;
}

export declare class KeyHelperDef {
  static generateRegistrationId(extendedRange: boolean): number;
  static generateIdentityKeyPair(): any;
  static generateIdentityKeyPairFormatted(): TypeDef.IdentityKeyPair;
  static importIdentityKeyPair(serialized: any): TypeDef.IdentityKeyPair;
  static importSignedPreKeyRecord(serialized: any): TypeDef.SignedPreKeyRecord;
  static importSignalProtocolAddress(name: any, deviceId: number): TypeDef.SignalProtocolAddress;
  static generatePreKeys(start: number, count: number): TypeDef.PreKeyRecord[];
  static generatePreKeysFormatted(start: number, count: number): TypeDef.PreKeyRecord[];
  static generateSignedPreKey(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number, raw?: boolean): any;
  static generateLastResortPreKey(): TypeDef.PreKeyRecord;
  static verifySignedPreKey(signingKey: TypeDef.ECPublicKey, message: any, signature: any): boolean;
  static generatePreKeys(start: number, count: number): TypeDef.PreKeyRecord[];
  static generateSignedPreKey(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number): TypeDef.SignedPreKeyRecord;
  static generateSignedPreKeyFormatted(identityKeyPair: TypeDef.IdentityKeyPair, signedPreKeyId: number): any;
}

export declare class UtilDef {
  static base64ToArrayBuffer(base64: string): ArrayBuffer;
  static arrayBufferToBase64(buffer: Iterable<number>): string;
  static atob(str: string);
  static btoa(str: string);
  static base64Encode(mixed: any): string;
  static base64Decode(base64Str: any): number[];
  static toString(value: any): string;
  static isEqualString(value: any, compared: any): boolean;
}

/**
 * The main entry point for Signal Protocol encrypt/decrypt operations.
 *
 * Once a session has been established with {@link SessionBuilder},
 * this class can be used for all encrypt/decrypt operations within
 * that session.
 *
 * @author Moxie Marlinspike
 */
export declare class SessionCipherDef {
  sessionStore: SessionStoreDef;
  identityKeyStore: IdentityKeyStoreDef;
  sessionBuilder: SessionBuilderDef;
  preKeyStore: PreKeyStoreDef;
  remoteAddress: TypeDef.SignalProtocolAddress;


  /**
   * Encrypt a message.
   *
   * @param  paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   */
  encrypt(paddedMessage: any): TypeDef.CiphertextMessage;

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
   *                               that corresponds to the PreKey ID in the message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  decrypt(ciphertext: any): any;

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
   * @param  callback   A callback that is triggered after decryption is complete,
   *                    but before the updated session state has been committed to the session
   *                    DB.  This allows some implementations to store the committed plaintext
   *                    to a DB first, in case they are concerned with a crash happening between
   *                    the time the session state is updated but before they're able to store
   *                    the plaintext to disk.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
   *                               that corresponds to the PreKey ID in the message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  decrypt(ciphertext: any, callback: any): any;

  /**
   * Construct a SessionCipher for encrypt/decrypt operations on a session.
   * In order to use SessionCipher, a session must have already been created
   * and stored using {@link SessionBuilder}.
   *
   * @param  sessionStore The {@link SessionStore} that contains a session for this recipient.
   * @param  remoteAddress  The remote address that messages will be encrypted to or decrypted from.
   */
  constructor(store: ISignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress);

  constructor(sessionStore: SessionStoreDef, preKeyStore: PreKeyStoreDef, signedPreKeyStore: SignedPreKeyStoreDef, identityKeyStore: IdentityKeyStoreDef, remoteAddress: TypeDef.SignalProtocolAddress);
}

export declare class PreKeyBundleDef {
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

export declare class ClientInfoDef {
  constructor(identityKey: TypeDef.IdentityKey, registrationId: number, deviceId: number, preKeys: any[], signedPreKeyId: number, signedPreKey: TypeDef.ECPublicKey, signedPreKeySignature: any);

  public getPreKeyBundle(): any;
}

export declare class ClientDef {
  public store: ISignalProtocolStore;
  public registrationId: number;
  public username: string;
  public deviceId: number;

  constructor(clientName: string, registrationId: number, deviceId: number);
  public hasContact(contactName: string): boolean;

  public exportRegistrationObj(): any;
  public serialize(): any;
  public addSession(contact: any, contactBundle: any): Promise<boolean>;
  public prepareMessage(contactName: string, message: string): Promise<string>;

  public encodeMessage(message: string): Promise<string>;

  public decodeMessage(message: string): Promise<any>;

  public decryptEncodedMessage(contactName: string, message: string): Promise<string>;
}

/**
 * SessionBuilder is responsible for setting up encrypted sessions.
 * Once a session has been established, {@link org.whispersystems.libsignal.SessionCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * Sessions are built from one of three different possible vectors:
 * <ol>
 *   <li>A {@link org.whispersystems.libsignal.state.PreKeyBundle} retrieved from a server.</li>
 *   <li>A {@link PreKeySignalMessage} received from a client.</li>
 * </ol>
 *
 * Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * @author Moxie Marlinspike
 */
export declare class SessionBuilderDef {
  sessionStore: SessionStoreDef;
  preKeyStore: PreKeyStoreDef;
  signedPreKeyStore: SignedPreKeyStoreDef;
  identityKeyStore: IdentityKeyStoreDef;
  remoteAddress: TypeDef.SignalProtocolAddress;

  process(sessionRecord: TypeDef.SessionRecord, message: any): any;
  process(preKey: PreKeyBundleDef): void;
  processV3(sessionRecord: TypeDef.SessionRecord, message: any): any;

  /**
   * Constructs a SessionBuilder
   * @param store The {@link SignalProtocolStore} to store all state information in.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  constructor(store: ISignalProtocolStore, remoteAddress: TypeDef.SignalProtocolAddress);

  /**
   * Constructs a SessionBuilder.
   *
   * @param sessionStore The {@link org.whispersystems.libsignal.state.SessionStore} to store the constructed session in.
   * @param preKeyStore The {@link  org.whispersystems.libsignal.state.PreKeyStore} where the client's local {@link org.whispersystems.libsignal.state.PreKeyRecord}s are stored.
   * @param identityKeyStore The {@link org.whispersystems.libsignal.state.IdentityKeyStore} containing the client's identity key information.
   * @param remoteAddress The address of the remote user to build a session with.
   */
  constructor(sessionStore: SessionStoreDef, preKeyStore: PreKeyStoreDef, signedPreKeyStore: SignedPreKeyStoreDef, identityKeyStore: IdentityKeyStoreDef, remoteAddress: TypeDef.SignalProtocolAddress);
}

/**
 * Provides an interface to identity information.
 *
 * @author Moxie Marlinspike
 */
export declare class IdentityKeyStoreDef {
  Direction: any; // SENDING, RECEIVING

  /**
   * Return the saved public identity key for a remote client
   *
   * @param address The address of the remote client
   * @return The public identity key, or null if absent
   */
  getIdentity(address: TypeDef.SignalProtocolAddress): TypeDef.IdentityKey;

  /**
   * Get the local client's identity key pair.
   *
   * @return The local client's persistent identity key pair.
   */
  getIdentityKeyPair(): TypeDef.IdentityKeyPair;

  /**
   * Return the local client's registration ID.
   * <p>
   * Clients should maintain a registration ID, a random number
   * between 1 and 16380 that's generated once at install time.
   *
   * @return the local client's registration ID.
   */
  getLocalRegistrationId(): number;

  /**
   * Save a remote client's identity key
   * <p>
   * Store a remote client's identity key as trusted.
   *
   * @param address     The address of the remote client.
   * @param identityKey The remote client's identity key.
   * @return True if the identity key replaces a previous identity, false if not
   */
  saveIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey): boolean;

  /**
   * Verify a remote client's identity key.
   * <p>
   * Determine whether a remote client's identity is trusted.  Convention is
   * that the Signal Protocol is 'trust on first use.'  This means that
   * an identity key is considered 'trusted' if there is no entry for the recipient
   * in the local store, or if it matches the saved key for a recipient in the local
   * store.  Only if it mismatches an entry in the local store is it considered
   * 'untrusted.'
   *
   * Clients may wish to make a distinction as to how keys are trusted based on the
   * direction of travel. For instance, clients may wish to accept all 'incoming' identity
   * key changes, while only blocking identity key changes when sending a message.
   *
   * @param address     The address of the remote client.
   * @param identityKey The identity key to verify.
   * @param direction   The direction (sending or receiving) this identity is being used for.
   * @return true if trusted, false if untrusted.
   */
  isTrustedIdentity(address: TypeDef.SignalProtocolAddress, identityKey: TypeDef.IdentityKey, direction: any): boolean;
}

/**
 * The interface to the durable store of session state information
 * for remote clients.
 *
 * @author Moxie Marlinspike
 */
export declare class SessionStoreDef {
  /**
   * Returns a copy of the {@link SessionRecord} corresponding to the recipientId + deviceId tuple,
   * or a new SessionRecord if one does not currently exist.
   * <p>
   * It is important that implementations return a copy of the current durable information.  The
   * returned SessionRecord may be modified, but those changes should not have an effect on the
   * durable session state (what is returned by subsequent calls to this method) without the
   * store method being called here first.
   *
   * @param address The name and device ID of the remote client.
   * @return a copy of the SessionRecord corresponding to the recipientId + deviceId tuple, or
   *         a new SessionRecord if one does not currently exist.
   */
  loadSession(address: TypeDef.SignalProtocolAddress): TypeDef.SessionRecord;

  /**
   * Returns all known devices with active sessions for a recipient
   *
   * @param name the name of the client.
   * @return all known sub-devices with active sessions.
   */
  getSubDeviceSessions(name: string): java.util.List<java.lang.Integer>;

  /**
   * Commit to storage the {@link SessionRecord} for a given recipientId + deviceId tuple.
   * @param address the address of the remote client.
   * @param record the current SessionRecord for the remote client.
   */
  storeSession(address: TypeDef.SignalProtocolAddress, record: TypeDef.SessionRecord): void;

  /**
   * Determine whether there is a committed {@link SessionRecord} for a recipientId + deviceId tuple.
   * @param address the address of the remote client.
   * @return true if a {@link SessionRecord} exists, false otherwise.
   */
  containsSession(address: TypeDef.SignalProtocolAddress): boolean;

  /**
   * Remove a {@link SessionRecord} for a recipientId + deviceId tuple.
   *
   * @param address the address of the remote client.
   */
  deleteSession(address: TypeDef.SignalProtocolAddress): void;

  /**
   * Remove the {@link SessionRecord}s corresponding to all devices of a recipientId.
   *
   * @param name the name of the remote client.
   */
  deleteAllSessions(name: string): void;
}

/**
 * An interface describing the local storage of {@link PreKeyRecord}s.
 *
 * @author Moxie Marlinspike
 */
export declare class PreKeyStoreDef {
  /**
   * Load a local PreKeyRecord.
   *
   * @param preKeyId the ID of the local PreKeyRecord.
   * @return the corresponding PreKeyRecord.
   * @throws InvalidKeyIdException when there is no corresponding PreKeyRecord.
   */
  loadPreKey(preKeyId: number): TypeDef.PreKeyRecord;

  /**
   * Store a local PreKeyRecord.
   *
   * @param preKeyId the ID of the PreKeyRecord to store.
   * @param record the PreKeyRecord.
   */
  storePreKey(preKeyId: number, record: TypeDef.PreKeyRecord);

  /**
   * @param preKeyId A PreKeyRecord ID.
   * @return true if the store has a record for the preKeyId, otherwise false.
   */
  containsPreKey(preKeyId: number): boolean;

  /**
   * Delete a PreKeyRecord from local storage.
   *
   * @param preKeyId The ID of the PreKeyRecord to remove.
   */
  removePreKey(preKeyId: number): void;
}

export declare class SignedPreKeyStoreDef {
  /**
   * Load a local SignedPreKeyRecord.
   *
   * @param signedPreKeyId the ID of the local SignedPreKeyRecord.
   * @return the corresponding SignedPreKeyRecord.
   * @throws InvalidKeyIdException when there is no corresponding SignedPreKeyRecord.
   */
  loadSignedPreKey(signedPreKeyId: number): TypeDef.SignedPreKeyRecord;

  /**
   * Load all local SignedPreKeyRecords.
   *
   * @return All stored SignedPreKeyRecords.
   */
  loadSignedPreKeys(): TypeDef.SignedPreKeyRecord[];

  /**
   * Store a local SignedPreKeyRecord.
   *
   * @param signedPreKeyId the ID of the SignedPreKeyRecord to store.
   * @param record the SignedPreKeyRecord.
   */
  storeSignedPreKey(signedPreKeyId: number, record: TypeDef.SignedPreKeyRecord): void;

  /**
   * @param signedPreKeyId A SignedPreKeyRecord ID.
   * @return true if the store has a record for the signedPreKeyId, otherwise false.
   */
  containsSignedPreKey(signedPreKeyId: number): boolean;

  /**
   * Delete a SignedPreKeyRecord from local storage.
   *
   * @param signedPreKeyId The ID of the SignedPreKeyRecord to remove.
   */
  removeSignedPreKey(signedPreKeyId: number): void;
}

export declare interface ISignalProtocolStore extends IdentityKeyStoreDef, PreKeyStoreDef, SessionStoreDef, SignedPreKeyStoreDef  {
}

export declare class MemorySignalProtocolStoreDef implements ISignalProtocolStore {
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

export declare class InMemorySignalProtocolStoreDef {
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
