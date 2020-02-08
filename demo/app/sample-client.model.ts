import { LibsignalProtocol } from 'nativescript-libsignal-protocol';

declare var java: any;

export class SampleClientModel {
  private random;
  private address: LibsignalProtocol.Type.SignalProtocolAddress;
  public store: any;
  
  private publicPreKeys: any[];
  private privatePreKeys: any[];
  private signedPreKey: any;
  private contacts: any;

  public registrationId: number;
  public username: string;
  public deviceId: number;

  constructor(clientName: string, registrationId: number, deviceId: number) {
    this.random = new java.util.Random();
    this.contacts = {};
    this.username = clientName;
    this.deviceId = deviceId;
    this.registrationId = registrationId;

    // console.log(`>> Starting Client [${clientName}] ID:[${registrationId} Device:[${deviceId}]`);
    this.address = LibsignalProtocol.Core.createSignalProtocolAddress(registrationId, deviceId);

    // Generate some keys for usage
    let identityKeyPair = LibsignalProtocol.KeyHelper.generateIdentityKeyPair();
    // console.log(`>> Client Identity Public [${Util.base64Encode(identityKeyPair.getPublicKey().serialize())}]`);

    // Generate initial prekeys for client session
    let preKeys = LibsignalProtocol.KeyHelper.generatePreKeysFormatted(this.random.nextInt(0xFFFFFF-101), 100);
    // let lastResortPreKeyRecord = LibsignalProtocol.KeyHelper.generateLastResortPreKeyRecord();
    this.signedPreKey = LibsignalProtocol.KeyHelper.generateSignedPreKey(identityKeyPair, this.random.nextInt(0xFFFFFF-1));
    // console.log(`>> Client Identity Generated 101 preKeys, 1 signedPreKey`);

    this.publicPreKeys = preKeys.map((_key) => {
      return {
        id: _key['keyId'],
        pubKey: _key['keyPair'].pubKey
      }
    });

    this.privatePreKeys = preKeys.map((_key) => {
      return _key['serialized']
    });

    this.store = LibsignalProtocol.Core.createMemorySignalProtocolStore(identityKeyPair, registrationId);
    // console.log(`>> Client Store created`);

    this.store.storeSignedPreKey(this.signedPreKey.getId(), this.signedPreKey);
    // console.log(`>> Client Added 1 SignedPreKey to Store`);

    preKeys.forEach((_key) => {
      let preKeyRecord = LibsignalProtocol.Core.importPreKeyRecord(LibsignalProtocol.Util.base64Decode(_key['serialized']));
      // console.log(`...storing #${preKeyRecord.getId()}`);
      this.store.storePreKey(preKeyRecord.getId(), preKeyRecord);
    });
    // console.log(`>> Client Added PreKeys to Store`);

    // this.store.storePreKey(lastResortPreKeyRecord.getId(), lastResortPreKeyRecord);
    // console.log(`>> Client Added LastResort PreKey to Store`);
  }

  public hasContact(contactName: string) {
    return !!(this.contacts.hasOwnProperty(contactName));
  }

  public exportRegistrationObj() {
    return {
      address: {
        name: this.address.getName(),
        deviceId: this.address.getDeviceId(),
        registrationId: this.store.getLocalRegistrationId()
      },
      identityPubKey: LibsignalProtocol.Util.base64Encode(this.store.getIdentityKeyPair().getPublicKey().serialize()),
      signedPreKey: {
        id: this.signedPreKey.getId(),
        pubKey: LibsignalProtocol.Util.base64Encode(this.signedPreKey.getKeyPair().getPublicKey().serialize()),
        signature: LibsignalProtocol.Util.base64Encode(this.signedPreKey.getSignature())
      },
      publicPreKeys: this.publicPreKeys,
    }
  }

  public serialize() {
    let serialize = {
      client: {
        registrationId: this.registrationId,
        username: this.username,
        deviceId: this.deviceId
      },
      contacts: this.contacts.map((_c) => {
        return {
          registrationId: _c.registrationId,
          deviceId: _c.deviceId,
          preKeyBundle: _c.preKeyBundle,
          sessionCipher: _c.sessionCipher
        }
      }),
      preKeys: this.privatePreKeys,
      signedPreKey: LibsignalProtocol.Util.base64Encode(this.signedPreKey.serialize()),
      identityKeyPair: LibsignalProtocol.Util.base64Encode(this.store.getIdentityKeyPair().serialize())
    };

    return JSON.stringify(serialize);
  }

  public addSession(contact: any, contactBundle: any): Promise<boolean> {
    try {
      // console.log(`>> Adding Session [${contact.name}][${contact.deviceId}][${contact.registrationId}] to Address:[${this.address.getName()}]`);

      // recreate SignalProtocolAddress
      let signalAddress = LibsignalProtocol.Core.createSignalProtocolAddress(contact.registrationId, contact.deviceId);

      // recreate PreKeyBundle
      let preKeyBundle = this.importPreKeyBundle(signalAddress, contactBundle);

      // create SessionBuilder
      let sessionBuilder = LibsignalProtocol.Core.createSessionBuilder(this.store, signalAddress);

      // import the PreKeyBundle into the SessionBuilder
      sessionBuilder.process(preKeyBundle);

      // create SessionCipher
      let sessionCipher = LibsignalProtocol.Core.createSessionCipher(this.store, signalAddress);

      this.contacts[contact.name] = {
        registrationId: contact.registrationId,
        deviceId: contact.deviceId,
        preKeyBundle: contactBundle,
        sessionCipher: sessionCipher,
        signalAddress: signalAddress
      };
      
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

    let cipher = this.contacts[contactName].sessionCipher;
    return Promise.resolve(this.encryptMessage(message, cipher));
  }

  public encodeMessage(message: string): Promise<string> {
    return Promise.resolve(LibsignalProtocol.Util.base64Encode(message));
  }

  public decodeMessage(message: string): Promise<any> {
    return Promise.resolve(LibsignalProtocol.Util.base64Decode(message));
  }

  public async decryptEncodedMessage(contactName: string, message: string) {
    if (!this.hasContact(contactName)) {
      throw new Error('missing_contact');
    }

    let decodedMessage = await this.decodeMessage(message);
    let cipher = this.contacts[contactName].sessionCipher;
    return Promise.resolve(this.decryptMessage(decodedMessage, cipher));
  }

  private importPreKeyBundle(signalAddress: any, importedData: any): any {
    let identityPubKey = LibsignalProtocol.Core.importIdentityKey(LibsignalProtocol.Util.base64Decode(importedData.identityPubKey));

    return LibsignalProtocol.Core.createPreKeyBundle(
      Number(signalAddress.getName()),
      Number(signalAddress.getDeviceId()),
      importedData.preKeyRecordId,
      LibsignalProtocol.Core.importPublicKey(LibsignalProtocol.Util.base64Decode(importedData.preKeyPublic)),
      importedData.signedPreKeyRecordId,
      LibsignalProtocol.Core.importPublicKey(LibsignalProtocol.Util.base64Decode(importedData.signedPreKeyPublic)),
      LibsignalProtocol.Util.base64Decode(importedData.signature),
      identityPubKey
    );
  }

  private encryptMessage(message: string, sessionCipher: any): any {
    let javaStr = new java.lang.String(message);
    return sessionCipher.encrypt(javaStr.getBytes("UTF-8")).serialize();
  }

  private decryptMessage(message: any, cipher) {
    let signalMessage = LibsignalProtocol.Core.createPreKeySignalMessage(message);
    let text = cipher.decrypt(signalMessage);
    return new java.lang.String(text).toString();
  }
}
