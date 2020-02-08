import { Observable } from 'tns-core-modules/data/observable';
import { LibsignalProtocol } from 'nativescript-libsignal-protocol';
import { Couchbase } from 'nativescript-couchbase-plugin';
import { request, getFile, getImage, getJSON } from "tns-core-modules/http";
import {
  getBoolean,
  setBoolean,
  getNumber,
  setNumber,
  getString,
  setString,
  hasKey,
  remove,
  clear
} from "tns-core-modules/application-settings";

interface SessionStateOld { 
  deviceId: number,
  registrationId: string,
  identityKeyPair: LibsignalProtocol.Type.IdentityKeyPair,
  preKeys: any[],
  signedPreKey: LibsignalProtocol.Type.SignedPreKeyRecord,
};

interface IdentityKeyPair {
  pubKey: string,
  privKey: string,
  serialized: string
};

interface SignedPreKey {
  keyId: number,
  keyPair: {
    pubKey: string,
    pubKey2: string,
    privKey: string
  },
  signature: string,
  serialized: string
}

interface SessionState {
  registrationId: string,
  deviceId: number,
  identity: IdentityKeyPair,
  signedPreKey: SignedPreKey,
  preKeys: any[]
};

interface MemoryState {
  deviceId: number,
  registrationId: string,
  identityKeyPair: IdentityKeyPair,
  signedPreKey: SignedPreKey,
  // needs to be a SignalProtocolStore impl
  // used to build sessions and handle messages
  // holds pre-keys for other users
  store: LibsignalProtocol.InMemorySignalProtocolStore,
  messages: any[],
  friends: any[],
  signalIdentityKeyPair: LibsignalProtocol.Type.IdentityKeyPair
};

const RECIPIENT_REGISTER_ID = 123;
const RECIPIENT_DEVICE_ID = 123;
const API = 'http://95f95557.ngrok.io';

export class HelloWorldModel extends Observable {
  public message: string;
  public identityModel: Observable;
  private database: any;
  private identityId: any;
  private sessionIdentity: any;
  private _sesh: any;
  // private memoryStore: LibsignalProtocol.InMemorySignalProtocolStore;
  private memoryState: any;
  private signalStore: LibsignalProtocol.MemorySignalProtocolStore;
  private signalAddress: LibsignalProtocol.Type.SignalProtocolAddress;
  // private libsignalProtocol: LibsignalProtocol;
  // private keyHelper: KeyHelper;

  constructor() {
    super();
    // clear();

    console.log('LibsignalProtocol');
    console.dir(LibsignalProtocol);

    console.log('keyhelper');
    console.dir(LibsignalProtocol.KeyHelper);

    this.database = new Couchbase('example');
    console.dir('database', this.database);

    this.identityModel = new Observable();
    this.identityModel.set('model', false);
    this.updateSesh(false);

    // this.memoryStore = new LibsignalProtocol.InMemorySignalProtocolStore();
    // console.dir(this.memoryStore);

    this.memoryState = {
      // local session vars
      deviceId: null,
      registrationId: null,
      identityKeyPair: null,
      signedPreKey: null,
      // needs to be a SignalProtocolStore impl
      // used to build sessions and handle messages
      // holds pre-keys for other users
      store: new LibsignalProtocol.InMemorySignalProtocolStore(),
      messages: [],
      friends: [],
      signalIdentityKeyPair: null
    };
    console.dir(this.memoryState);

    console.log('--- begin demo ---');

    let test = new LibsignalProtocol.TestCore();
    test.testBasicSimultaneousInitiate();

    /**
     * Save IdentityKeyPair
     * 
     * setString('identityKeyPair', LibsignalProtocol.Util.arrayBufferToBase64(_identityKeyPair.serialize()));
     * >> stores as base64 encoded string
     * >> "CiEF8TsN0GpaQga89AM+Jlr2zhIORu1SC/f9PBE7eE1R7GISIABwEYdKq/TNnBkrOpDcRp5UXjZrDQvmH93pog3oN0pr"
     * 
     * importedIdentityKeyPair = getString('identityKeyPair');
     * RestoredIdentityKeyPair = LibsignalProtocol.KeyHelper.importIdentityKeyPair(importedIdentityKeyPair);
     *
     */
  }

  get sesh(): any {
    return this._sesh;
  }

  set sesh(value: any) {
    if (this._sesh !== value) {
      this._sesh = value;
      this.notifyPropertyChange("sesh", value);
    }
  }

  private updateSesh(msg: any) {
    this.sesh = msg;
  }

  private testSession() {
    let aliceSessionRecord = LibsignalProtocol.Core.createSessionRecord();
    let bobSessionRecord = LibsignalProtocol.Core.createSessionRecord();

    this.initializeSession(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

  }

  private initializeSession(aliceSessionState: any, bobSessionState: any) {
  }

  private name() {
    let aliceIdentity = LibsignalProtocol.KeyHelper.generateIdentityKeyPair();
    let bobIdentity = LibsignalProtocol.KeyHelper.generateIdentityKeyPair();    

    let aliceAddress = LibsignalProtocol.KeyHelper.importSignalProtocolAddress(1111, 1);
    let bobAddress = LibsignalProtocol.KeyHelper.importSignalProtocolAddress(2222, 1);

    console.log(`alice:: register=${aliceAddress.getName()} device=${aliceAddress.getDeviceId()}`);
    console.log(`bob:: register=${bobAddress.getName()} device=${bobAddress.getDeviceId()}`);

    let aliceStore = new LibsignalProtocol.MemorySignalProtocolStore(aliceIdentity, Number(aliceAddress.getName()));
    let bobStore = new LibsignalProtocol.MemorySignalProtocolStore(bobIdentity, Number(bobAddress.getName()));

    // aliceStore.storeSession(aliceAddress, 1);
    // bobStore.storeSession(bobAddress, 1)

    // SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    // SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    // aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
    // bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

    // SessionCipher     aliceCipher    = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
    // SessionCipher     bobCipher      = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

    // byte[]            alicePlaintext = "This is a plaintext message.".getBytes();
    // CiphertextMessage message        = aliceCipher.encrypt(alicePlaintext);
    // byte[]            bobPlaintext   = bobCipher.decrypt(new SignalMessage(message.serialize()));

    // assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

    // byte[]            bobReply      = "This is a message from Bob.".getBytes();
    // CiphertextMessage reply         = bobCipher.encrypt(bobReply);
    // byte[]            receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

    // assertTrue(Arrays.equals(bobReply, receivedReply));

    // List<CiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
    // List<byte[]>            alicePlaintextMessages  = new ArrayList<>();

    // for (int i=0;i<50;i++) {
    //   alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
    //   aliceCiphertextMessages.add(aliceCipher.encrypt(("смерть за смерть " + i).getBytes()));
    // }

    // long seed = System.currentTimeMillis();

    // Collections.shuffle(aliceCiphertextMessages, new Random(seed));
    // Collections.shuffle(alicePlaintextMessages, new Random(seed));

    // for (int i=0;i<aliceCiphertextMessages.size() / 2;i++) {
    //   byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
    //   assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
    // }

    // List<CiphertextMessage> bobCiphertextMessages = new ArrayList<>();
    // List<byte[]>            bobPlaintextMessages  = new ArrayList<>();

    // for (int i=0;i<20;i++) {
    //   bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
    //   bobCiphertextMessages.add(bobCipher.encrypt(("смерть за смерть " + i).getBytes()));
    // }

    // seed = System.currentTimeMillis();

    // Collections.shuffle(bobCiphertextMessages, new Random(seed));
    // Collections.shuffle(bobPlaintextMessages, new Random(seed));

    // for (int i=0;i<bobCiphertextMessages.size() / 2;i++) {
    //   byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
    //   assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
    // }

    // for (int i=aliceCiphertextMessages.size()/2;i<aliceCiphertextMessages.size();i++) {
    //   byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
    //   assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
    // }

    // for (int i=bobCiphertextMessages.size() / 2;i<bobCiphertextMessages.size(); i++) {
    //   byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
    //   assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
    // }
  }

  private importSessionState(state: SessionState): Promise<any> {
    console.log('===- IMPORT SESSION STATE -===');
    console.log(`DEVICEID::${state.deviceId}`);
    console.log(`REGID::${state.registrationId}`);
    // build a new store on each account
    // when server based this should only happen once
    this.memoryState.store = new LibsignalProtocol.InMemorySignalProtocolStore();

    this.memoryState.deviceId = Number(state.deviceId);
    this.memoryState.registrationId = state.registrationId;

    // needs to be in SignalProtocolStore
    this.memoryState.store.put('registrationId', state.registrationId);

    this.memoryState.identityKeyPair = state.identity;

    // needs to be in SignalProtocolStore
    this.memoryState.store.put('identityKey', state.identity);

    // Store both sets of keys in the client/store
    this.memoryState.preKeys = state.preKeys;

    // Store these keys in the client, others will make requests to you for these
    state.preKeys.forEach(({keyId, keyPair}) => {
      // needs to be in SignalProtocolStore
      this.memoryState.store.storePreKey(keyId, keyPair);
    });

    this.memoryState.signedPreKey = state.signedPreKey;

    // needs to be in SignalProtocolStore
    this.memoryState.store.storeSignedPreKey(state.signedPreKey.keyId, state.signedPreKey.keyPair);

    this.memoryState.signalIdentityKeyPair = LibsignalProtocol.KeyHelper.importIdentityKeyPair(LibsignalProtocol.Util.base64Decode(state.identity.serialized));

    this.signalStore = LibsignalProtocol.Core.createSignalProtocolStore(this.memoryState.signalIdentityKeyPair, Number(state.registrationId));

    this.signalAddress = LibsignalProtocol.Core.createSignalProtocolAddress(this.memoryState.registrationId, this.memoryState.deviceId);

    return Promise.resolve(this.memoryState);
  }

  private generateNewSessionIdentity(): any {
    let identityKeyPair: LibsignalProtocol.Type.IdentityKeyPair;
    let preKeys: any[];
    let signedPreKey: LibsignalProtocol.Type.SignedPreKeyRecord;
    let signedPreKeyPair: LibsignalProtocol.Type.ECKeyPair;
    
    identityKeyPair   = LibsignalProtocol.KeyHelper.generateIdentityKeyPair();
    preKeys           = LibsignalProtocol.KeyHelper.generatePreKeys(0, 5);
    signedPreKey      = LibsignalProtocol.KeyHelper.generateSignedPreKey(identityKeyPair, 1, true);
    signedPreKeyPair  = signedPreKey.getKeyPair();

    return {
      registrationId: `${LibsignalProtocol.KeyHelper.generateRegistrationId()}`,
      deviceId: 123,
      identity: {
        pubKey: LibsignalProtocol.Util.arrayBufferToBase64(identityKeyPair.getPublicKey().serialize()),
        privKey: LibsignalProtocol.Util.arrayBufferToBase64(identityKeyPair.getPrivateKey().serialize()),
        serialized: LibsignalProtocol.Util.arrayBufferToBase64(identityKeyPair.serialize()),
      },
      signedPreKey: {
        keyId: signedPreKey.getId(),
        keyPair: {
          pubKey: LibsignalProtocol.Util.base64Encode(signedPreKeyPair.getPublicKey().serialize()),
          privKey: LibsignalProtocol.Util.arrayBufferToBase64(signedPreKeyPair.getPrivateKey().serialize()),
        },
        signature: LibsignalProtocol.Util.arrayBufferToBase64(signedPreKey.getSignature()),
        serialized: LibsignalProtocol.Util.arrayBufferToBase64(signedPreKey.serialize()),
      },
      preKeys: preKeys
    };
  }

  private async pushSessionToServer() {
    console.log("===- PUSH SESSION TO SERVER -===");

    // console.dir(this.memoryState);
    // console.dir(this.memoryState.store);
    
    let identity: IdentityKeyPair = await this.memoryState.store.getIdentityKeyPair();

    console.dir(this.memoryState.signedPreKey);

    let requestObj = {
      deviceId: this.memoryState.deviceId,
      registrationId: await this.memoryState.store.getLocalRegistrationId(),
      identityKey: identity.pubKey,
      signedPreKey: {
        keyId: this.memoryState.signedPreKey.keyId,
        publicKey: this.memoryState.signedPreKey.keyPair.pubKey,
        signature: this.memoryState.signedPreKey.signature
      },
      // Generate preKey bundle for others to use, these get sent to the server
      preKeys: this.memoryState.preKeys.map((preKey) => {
        return {
          keyId: parseInt(preKey.keyId),
          // Only send public pre key and ID
          publicKey: preKey.keyPair.pubKey
        };
      })
    };

    console.log('--- requestObj ---');
    console.dir(requestObj);
    console.log('---');

    request({
      // url: "https://httpbin.org/put",
      url: `${API}/keys`,
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      content: JSON.stringify(requestObj)
    }).then((response) => {
      console.log('-- response');
      console.dir(response);
      console.log('-- content');
      console.log(response.content);
      console.log('-- content.toJSON');
      console.dir(response.content.toJSON());
    }, (e) => {
      console.log('Error occurred');
      console.log(e.message ? e.message : e);
      console.dir(e);
    });
  }

  private async sendToServer() {
    console.log("===- SEND TO SERVER -===");

    try {
      let aliceIdentity = this.generateNewSessionIdentity();
      let aliceAddress = LibsignalProtocol.Core.createSignalProtocolAddress(aliceIdentity.registrationId, aliceIdentity.deviceId);

      console.log('s1', this.signalStore.getLocalRegistrationId());
      console.log('s2', this.signalAddress.getName());

      let myAdress = this.signalAddress;

      // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
      
      // ME
      // let sessionBuilder = LibsignalProtocol.Core.createSessionBuilder(this.signalStore, this.signalAddress);
      
      // let importedSigned = LibsignalProtocol.Core.importSignedPreKey(LibsignalProtocol.Util.base64Decode(this.memoryState.signedPreKey.serialized));
      
      // let importedPre = LibsignalProtocol.Core.importPreKeyRecord(LibsignalProtocol.Util.base64Decode(this.memoryState.preKeys[1].serialized));

      // ALICE
      let sessionBuilder = LibsignalProtocol.Core.createSessionBuilder(this.signalStore, aliceIdentity.signalAddress);
      
      let importedSigned = LibsignalProtocol.Core.importSignedPreKey(LibsignalProtocol.Util.base64Decode(aliceIdentity.signedPreKey.serialized));
      
      let importedPre = LibsignalProtocol.Core.importPreKeyRecord(LibsignalProtocol.Util.base64Decode(aliceIdentity.preKeys[1].serialized));

      let identityKeyPair = LibsignalProtocol.KeyHelper.importIdentityKeyPair(LibsignalProtocol.Util.base64Decode(aliceIdentity.identity.serialized));

      console.log(LibsignalProtocol.Util.base64Encode(importedSigned.serialize()));

      console.log(importedPre.getId());

      console.dir({
        redId: aliceIdentity.registrationId,
        devId: aliceIdentity.deviceId,
        preId: importedPre.getId(),
        prePubId: LibsignalProtocol.Util.base64Encode(importedPre.getKeyPair().getPublicKey().serialize()),
        signedId: importedSigned.getId(),
        signedPub: LibsignalProtocol.Util.base64Encode(importedSigned.getKeyPair().getPublicKey().serialize()),
        signedSig: LibsignalProtocol.Util.base64Encode(importedSigned.getSignature()),
        idKey: LibsignalProtocol.Util.base64Encode(identityKeyPair.getPublicKey().serialize())
      });

      let preKeyBundle = LibsignalProtocol.Core.createPreKeyBundle(
        aliceIdentity.registrationId,
        aliceIdentity.deviceId,
        importedPre.getId(),
        importedPre.getKeyPair().getPublicKey(),
        importedSigned.getId(),
        importedSigned.getKeyPair().getPublicKey(),
        importedSigned.getSignature(),
        identityKeyPair.getPublicKey()
      );

      console.log('device', preKeyBundle.getDeviceId());
      console.log('preKey', preKeyBundle.getPreKeyId());

      // Build a session with a PreKey retrieved from the server.
      sessionBuilder.process(preKeyBundle);

      // // Encrypt a message
      let recipient = LibsignalProtocol.Core.createSignalProtocolAddress(aliceIdentity.registrationId, aliceIdentity.deviceId);

      console.log('recipient', recipient.getName());

      let sessionCipher = LibsignalProtocol.Core.createSessionCipher(this.signalStore, recipient);

      let foo = new java.lang.String("Hello World!");

      console.log('raw message', foo);

      let message = sessionCipher.encrypt(foo.getBytes("UTF-8"));

      console.log('encrypted message', LibsignalProtocol.Util.base64Encode(message.serialize()));

      console.log('---done');
    } catch (err) {
      console.log('UNABLE TO SEND');
      console.log(err);
    }
  }

  private async pullFromServer() {
    console.log("===- PULL FROM SERVER -===");

    try {

      request({
        // url: "https://httpbin.org/put",
        url: `${API}/messages?deviceId=${this.memoryState.deviceId}&registrationId=${await this.memoryState.store.getLocalRegistrationId()}`,
        method: "GET"
      }).then(async (response) => {
        if (response.statusCode !== 200) {
          console.log('>> BAD RESPONSE');
          console.log(response.content);
          return;
        }

        console.log('...parsing encrypted data');
        let encryptedMessages = response.content.toJSON();
        console.dir(encryptedMessages);


        // for (let _msg of encryptedMessages) {
        //   console.log(`...got ${_msg.key}`);
        // }

        if (!encryptedMessages && encryptedMessages.length === 0) {
          console.log('>> NO CONTENT');
          console.log(response.content);
          return;
        }

        let encryptedMessage = encryptedMessages[0];
        let registrationId = Number(encryptedMessage.value.destinationRegistrationId);
        let deviceId = Number(encryptedMessage.value.destinationDeviceId);

        let fromRegistrationId = Number(encryptedMessage.value.registrationId);
        let fromDeviceId = Number(encryptedMessage.value.deviceId);

        console.log(`Received message from device [${fromDeviceId}] registration [${fromRegistrationId}]`);
        console.log(`Message to device [${deviceId}] registration [${registrationId}]`, encryptedMessage);

        let fromAddress, sessionCipher;

        try {
          fromAddress = LibsignalProtocol.Core.createSignalProtocolAddress(Number(fromRegistrationId), Number(fromDeviceId));

          console.log('fromAddress', fromAddress.getName());

          let msgBytes = new java.lang.String(encryptedMessage.value.ciphertextMessage.body).getBytes();
          // console.dir(new java.lang.String(encryptedMessage.value.ciphertextMessage.body).getBytes());
          console.log(msgBytes);

          // console.log(LibsignalProtocol.Util.rawciphertextToBinary(encryptedMessage.value.ciphertextMessage.body));

          // sessionCipher = LibsignalProtocol.Core.createSessionCipher(this.signalStore, fromAddress);
        } catch (err) {
          console.log('bad cipher');
          console.log(err);
        }

        console.log('encrypted Message');
        console.log(encryptedMessage.value.ciphertextMessage.body);

        // try {
        //   let plaintext;
        //   if (encryptedMessage.value.ciphertextMessage.type === 3) {
        //     console.log('--- Cipher message type 3: decryptPreKeyWhisperMessage');
        //     plaintext = await sessionCipher.decrypt(encryptedMessage.value.body);
        //   } else {
        //     console.log('--- Cipher message type 1: decryptWhisperMessage');
        //     plaintext = await sessionCipher.decrypt(encryptedMessage.value.body);
        //   }

        //   console.log('plaintext?', plaintext);
        // } catch (err) {
        //   console.log('unable to decrypt');
        //   console.log(err);
        // }

      }, (e) => {
        console.log('Error occurred');
        console.log(e.message ? e.message : e);
        console.dir(e);
      });
    } catch(err) {
      console.log('UNABLE TO PULL');
      console.log(err);
    }


    //             let fromAddress = new ls.SignalProtocolAddress(Number(registrationId), Number(deviceId));
    //             let sessionCipher = new ls.SessionCipher(state.store, fromAddress);

    //             console.debug(`Encrypted message:`, message.value.ciphertextMessage.body);
    //             let plaintext;
    //             if (message.value.ciphertextMessage.type === 3) {
    //                 console.debug(`Cipher message type 3: decryptPreKeyWhisperMessage`);
    //                 plaintext = await sessionCipher.decryptPreKeyWhisperMessage(message.value.ciphertextMessage.body, 'binary');
    //                 commit('commit-friend', `${deviceId}-${registrationId}`);
    //             } else if (message.value.ciphertextMessage.type === 1) {
    //                 console.debug(`Cipher message type 1: decryptWhisperMessage`);
    //                 plaintext = await sessionCipher.decryptWhisperMessage(message.value.ciphertextMessage.body, 'binary');
    //             }

    //             let decryptedMessage = util.toString(plaintext);
    //             console.debug(`Decrypted message:`, decryptedMessage);
    //             commit('commit-message', {
    //                 ...message.value,
    //                 message: decryptedMessage,
    //             });
    //             // delete message on receipt
    //             await api.delete(`/messages?key=${message.key}`);
    //             console.debug(`Read receipt sent for key:`, message.key);
    //         }
    //     }
    // } catch (ex) {
    //     console.error(ex);
    // }
  }

  public async onTapGenerate() {
    console.log("===- GENERATE -===");

    this.sessionIdentity = {};

    if (hasKey('sessionIdentity')) {
      console.log("...RESTORING SESSION");
      try {
        this.sessionIdentity = JSON.parse(getString('sessionIdentity'));
      } catch (err) {
        console.log('...UNABLE TO RESTORE IDENTITY');
        console.log(err);
        return;
      }
    } else {
      console.log("...GENERATING SESSION");
      this.sessionIdentity = this.generateNewSessionIdentity();

      console.log("...SAVING SESSION");
      setString('sessionIdentity', JSON.stringify(this.sessionIdentity));
    }

    this.identityId = this.database.createDocument(this.sessionIdentity);

    console.log('SESSION IDENTITY LOADED');
    // console.dir(this.sessionIdentity);
    console.dir(this.database.getDocument(this.identityId));
    console.dir(this.sessionIdentity.signedPreKey);
    this.identityModel.set('model', this.sessionIdentity);
    this.updateSesh(this.sessionIdentity);
    
    await this.importSessionState(this.sessionIdentity);
  }

  public onTapRegister(): void {
    console.log("===- REGISTER -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pushing to server');
    this.pushSessionToServer();
  }

  public onTapPull(): void {
    console.log("===- Pull -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pulling from server');
    this.pullFromServer();
  }

  public onTapSend(): void {
    console.log("===- Send -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pulling from server');
    this.sendToServer();
  }

  public test() {
    let registrationId, identityKeyPair, prekeys, signedPreKey, _identityKeyPair;

    clear();

    console.log('===- Demo1 -===');

    if (hasKey('registrationId')) {
      console.log('\t import registrationId');
    } else {
      console.log('\t set registrationId');
      setNumber('registrationId', LibsignalProtocol.KeyHelper.generateRegistrationId());
    }

    if (hasKey('identityKeyPair')) {
      console.log('\t import identityKeyPair');
    } else {
      _identityKeyPair = LibsignalProtocol.KeyHelper.generateIdentityKeyPair();
      setString('identityKeyPair', LibsignalProtocol.Util.arrayBufferToBase64(_identityKeyPair.serialize()));

      console.log('\t set identityKeyPair');
      console.log('\t -- serialize', _identityKeyPair.serialize());
      
      console.log('\t -- identityKeyPair.pub', _identityKeyPair.getPublicKey().serialize());
      console.log('\t -- identityKeyPair.priv', _identityKeyPair.getPrivateKey().serialize());

      console.log('\t -- identityKeyPair.pub64', LibsignalProtocol.Util.arrayBufferToBase64(_identityKeyPair.getPublicKey().serialize()));
      console.log('\t -- identityKeyPair.priv64', LibsignalProtocol.Util.arrayBufferToBase64(_identityKeyPair.getPrivateKey().serialize()));
    }

    registrationId  = getNumber('registrationId');
    identityKeyPair = getString('identityKeyPair');

    // console.log('registrationId', registrationId);
    console.log('identityKeyPair', identityKeyPair);

    // let buff = LibsignalProtocol.KeyHelper.base64ToArrayBuffer(identityKeyPair);
    let buff = LibsignalProtocol.Util.base64Decode(identityKeyPair);

    // console.log('buff', buff);
    let MainIdentityKeyPair = LibsignalProtocol.KeyHelper.importIdentityKeyPair(buff);

    console.log('\t set MainIdentityKeyPair');
    console.log('\t -- serialize', MainIdentityKeyPair.serialize());
    console.log('\t -- Exported:', LibsignalProtocol.Util.arrayBufferToBase64(MainIdentityKeyPair.serialize()));
      
    console.log('\t -- MainIdentityKeyPair.pub', MainIdentityKeyPair.getPublicKey().serialize());
    console.log('\t -- MainIdentityKeyPair.priv', MainIdentityKeyPair.getPrivateKey().serialize());

    console.log('\t -- MainIdentityKeyPair.pub64', LibsignalProtocol.Util.arrayBufferToBase64(MainIdentityKeyPair.getPublicKey().serialize()));
    console.log('\t -- MainIdentityKeyPair.priv64', LibsignalProtocol.Util.arrayBufferToBase64(MainIdentityKeyPair.getPrivateKey().serialize()));

    prekeys = LibsignalProtocol.KeyHelper.generatePreKeys(0, 5);

    console.dir(prekeys);

    signedPreKey = LibsignalProtocol.KeyHelper.generateSignedPreKey(MainIdentityKeyPair, 1, true);

    console.dir(signedPreKey);

    console.log('\t set signedPreKey');
    console.log('\t -- serialize', signedPreKey.serialize());
    console.log('\t -- Exported:', LibsignalProtocol.Util.arrayBufferToBase64(signedPreKey.serialize()));
  
    console.log('\t -- signedPreKey.sig', signedPreKey.getSignature());
    console.log('\t -- signedPreKey.sig64', LibsignalProtocol.Util.base64Encode(signedPreKey.getSignature()));

    let exportSignedPreKey = LibsignalProtocol.Util.base64Encode(signedPreKey.serialize());

    let importSigned = LibsignalProtocol.KeyHelper.importSignedPreKeyRecord(LibsignalProtocol.Util.base64Decode(exportSignedPreKey));

    console.log('\t imported signedPreKey');
    console.log('\t -- serialize', importSigned.serialize());
    console.log('\t -- serialize64', LibsignalProtocol.Util.base64Encode(importSigned.serialize()));
  
    console.log('\t -- signedPreKey.sig', importSigned.getSignature());
    console.log('\t -- signedPreKey.sig64', LibsignalProtocol.Util.base64Encode(importSigned.getSignature()));

    // console.log('pubkey match', _identityKeyPair.getPublicKey().equals(MainIdentityKeyPair.getPublicKey()));
    // console.log('privkey match', _identityKeyPair.getPrivateKey().equals(MainIdentityKeyPair.getPrivateKey()));
    // console.log('identity match', _identityKeyPair.equals(MainIdentityKeyPair));

    let OtherIdentityKeyPair = LibsignalProtocol.KeyHelper.importIdentityKeyPair(LibsignalProtocol.Util.base64Decode(identityKeyPair));

    // console.log('\t set OtherIdentityKeyPair');
    // console.log('\t -- OtherIdentityKeyPair.pub', OtherIdentityKeyPair.getPublicKey().serialize());
    // console.log('\t -- OtherIdentityKeyPair.priv', OtherIdentityKeyPair.getPrivateKey().serialize());
    // console.log('\t -- Exported:', LibsignalProtocol.Util.base64Encode(OtherIdentityKeyPair.serialize()));

    // console.log('---');

    // console.log('pubkey match', _identityKeyPair.getPublicKey().equals(MainIdentityKeyPair.getPublicKey()));
    // console.log('privkey match', _identityKeyPair.getPrivateKey().equals(MainIdentityKeyPair.getPrivateKey()));
    // console.log('identity match', _identityKeyPair.equals(MainIdentityKeyPair));

    // console.log('---');

    // console.log('pubkey match', MainIdentityKeyPair.getPublicKey().equals(MainIdentityKeyPair.getPublicKey()));
    // console.log('privkey match', MainIdentityKeyPair.getPrivateKey().equals(MainIdentityKeyPair.getPrivateKey()));
    // console.log('identity match', MainIdentityKeyPair.equals(MainIdentityKeyPair));

    // console.log('---');

    // console.log('pubkey match', MainIdentityKeyPair.getPublicKey().equals(OtherIdentityKeyPair.getPublicKey()));
    // console.log('privkey match', MainIdentityKeyPair.getPrivateKey().equals(OtherIdentityKeyPair.getPrivateKey()));
    // console.log('identity match', MainIdentityKeyPair.equals(OtherIdentityKeyPair));

    console.dir(MainIdentityKeyPair);
  }
}
