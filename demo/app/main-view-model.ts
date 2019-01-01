import { Observable } from 'tns-core-modules/data/observable';
import { LibsignalProtocol } from 'nativescript-libsignal-protocol';
import { Couchbase } from 'nativescript-couchbase-plugin';
import TestCore from './test-core';

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

interface IIdentityKeyPair {
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
  identity: IIdentityKeyPair,
  signedPreKey: SignedPreKey,
  preKeys: any[]
};

const SignalKeyHelper = LibsignalProtocol.KeyHelper;
const Base64Encode = LibsignalProtocol.Util.base64Encode;

export class HelloWorldModel extends Observable {
  public message: string;
  public identityModel: Observable;
  private database: any;
  private identityId: any;
  private sessionIdentity: any;
  private _sesh: any;
  private memoryState: any;
  private signalStore;
  private signalAddress;

  constructor() {
    super();
    
    // uncomment to clear application setting storage
    // clear();

    // output LibsignalProtocol available classes
    console.log('===- LibsignalProtocol -===');
    console.dir(LibsignalProtocol);

    // set example database
    this.database = new Couchbase('example');

    // set observable model for vanilla nativescript view changes
    this.identityModel = new Observable();
    this.identityModel.set('model', false);
    this.updateSesh(false);

    /**
     * Local session variables...
     * 
     * `store` is not a reference to the raw JAVA object, but instead
     * a wrapped "recreated" class which exposes methods the original
     * allows.
     */
    this.memoryState = {
      deviceId: null,
      registrationId: null,
      identityKeyPair: null,
      signedPreKey: null,
      store: new LibsignalProtocol.InMemorySignalProtocolStore(),
      messages: [],
      friends: [],
      signalIdentityKeyPair: null
    };

    console.log('--- begin demo ---');

    // Choose your own demo adventure!
    // Defaults to running with a local session controlled by the Demo application...

    // Uncomment to demonstrate a new session being generated!
    // this.demo_generateNewSessionIdentity();

    // Uncomment to demonstrate a sample encrypt/decrypt session between ALICE and BOB
    // let testCore = new TestCore();
    // testCore.testBasicSimultaneousInitiate();

    // Uncomment to demonstrate a simple client interface!
    // this.demo_ClientSessionInit();

    // Uncomment to demonstrate another client interface!
    // this.demo_ClientConversationInit();
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

  /**
   * Generates a new identity session.
   * If there was no session previously stored, it will generate a new one.
   * If there was a session stored, it will restore it.
   */
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
      this.sessionIdentity = this.demo_generateNewSessionIdentity();

      console.log("...SAVING SESSION");
      setString('sessionIdentity', JSON.stringify(this.sessionIdentity));
    }

    this.identityId = this.database.createDocument(this.sessionIdentity);

    console.log('SESSION IDENTITY LOADED');
    console.dir(this.database.getDocument(this.identityId));
    console.dir(this.sessionIdentity.signedPreKey);
    this.identityModel.set('model', this.sessionIdentity);
    this.updateSesh(this.sessionIdentity);
    
    await this.importSessionState(this.sessionIdentity);
  }

  /**
   * Registers a session "remotely" to a server
   */
  public onTapRegister(): void {
    console.log("===- REGISTER -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pushing to server');
    this.pushSessionToServer();
  }

  /**
   * "Pulls" a session from a server
   */
  public onTapPull(): void {
    console.log("===- Pull -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pulling from server');
    this.pullFromServer();
  }

  /**
   * "Sends" session to a server
   */
  public onTapSend(): void {
    console.log("===- OnTapSend -===");

    if (!this.memoryState.registrationId) {
      console.log('...no details to register');
      return;
    }

    console.log('...pulling from server');
    this.sendToServer();
  }

  /**
   * Outputs a new session identity generated with the Libsignal Protocol.
   * 
   * `identityKeyPair` is a raw reference to the JAVA object `IdentityKeyPair`
   * as such, the exported values must be `serialized` before being usable.
   * 
   * @returns The generated session identity as a JSON object.
   */
  public demo_generateNewSessionIdentity(): any {
    let identityKeyPair: LibsignalProtocol.Type.IdentityKeyPair;
    let preKeys: any[];
    let signedPreKey: LibsignalProtocol.Type.SignedPreKeyRecord;
    let signedPreKeyPair: LibsignalProtocol.Type.ECKeyPair;
    let registrationId: number;
    
    registrationId	  = SignalKeyHelper.generateRegistrationId();
    identityKeyPair   = SignalKeyHelper.generateIdentityKeyPair();
    preKeys           = SignalKeyHelper.generatePreKeysFormatted(0, 1);
    signedPreKey      = SignalKeyHelper.generateSignedPreKeyFormatted(identityKeyPair, 1);

    let sessionIdentity = {
      registrationId: `${registrationId}`,
      deviceId: 123,
      identity: {
        pubKey: Base64Encode(identityKeyPair.getPublicKey().serialize()),
        privKey: Base64Encode(identityKeyPair.getPrivateKey().serialize()),
        serialized: Base64Encode(identityKeyPair.serialize()),
      },
      signedPreKey: signedPreKey,
      preKeys: preKeys
    };

    console.log(sessionIdentity);
    return sessionIdentity;
  }

  /**
   * This demo runs through a series of messages between ALICE and BOB
   * in a direct conversation manner. There are three tests which run 5 messages
   * back and forth between two clients.
   */
  public async demo_ClientSessionInit() {
    console.log('===- DEMO -- ClientSession -===');
    
    let aliceClient     = new LibsignalProtocol.Client('userAlice', 2222, 123);
    let aliceClientReg  = aliceClient.exportRegistrationObj();

    let bobClient     =  new LibsignalProtocol.Client('userBob', 1111, 123);
    let bobClientReg  = bobClient.exportRegistrationObj();

    let aliceClientInfo = new LibsignalProtocol.ClientInfo(
      aliceClientReg.identityPubKey,
      aliceClientReg.address.registrationId,
      aliceClientReg.address.deviceId,
      aliceClientReg.preKeys,
      aliceClientReg.signedPreKey.id,
      aliceClientReg.signedPreKey.pubKey,
      aliceClientReg.signedPreKey.signature
    );

    let bobClientInfo = new LibsignalProtocol.ClientInfo(
      bobClientReg.identityPubKey,
      bobClientReg.address.registrationId,
      bobClientReg.address.deviceId,
      bobClientReg.preKeys,
      bobClientReg.signedPreKey.id,
      bobClientReg.signedPreKey.pubKey,
      bobClientReg.signedPreKey.signature
    );

    let alicePreKeyBundle = aliceClientInfo.getPreKeyBundle();
    let bobPreKeyBundle   = bobClientInfo.getPreKeyBundle();

    await aliceClient.addSession(bobClientReg.address, bobPreKeyBundle);
    console.log('...ALICE ADDED BOB SESSION');

    await bobClient.addSession(aliceClientReg.address, alicePreKeyBundle);
    console.log('...BOB ADDED ALICE SESSION');

    console.log('sanity checks...', {
      bob2alice_contact: bobClient.hasContact(aliceClientReg.address.name),
      bob2alice_session: bobClient.hasSession(aliceClientReg.address.name),
      alice2bob_contact: aliceClient.hasContact(bobClientReg.address.name),
      alice2bob_session:  aliceClient.hasSession(bobClientReg.address.name)
    });

    // let bobCipher = aliceClient.getContact('userBob');
    // console.dir(bobCipher);
    // let bobSessionRecord = aliceClient.getSessionRecord('userBob');
    // console.log('fresh?', bobSessionRecord.isFresh());
    // console.log('serial?', LibsignalProtocol.Util.base64Encode(bobSessionRecord.serialize()));
    

    if (!bobClient.hasContact(aliceClientReg.address.name) ||
        !aliceClient.hasContact(bobClientReg.address.name)) {
      console.log("Unable to continue... clients are missing eachother's contact details...");
      throw new Error('Something went wrong while adding demo sessions...');
    }

    if (!bobClient.hasSession(aliceClientReg.address.name) ||
        !aliceClient.hasSession(bobClientReg.address.name)) {
      console.log("Unable to continue... clients are missing eachother's sessions...");
      throw new Error('Something went wrong while adding demo sessions...');
    }

    let bobToAliceTests = [
      'pixxlated',
      'coffee break',
      'lofi all day',
      'all work no play',
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut quis ornare velit. Nulla venenatis porta dolor sodales efficitur. Sed ipsum tellus, efficitur ut aliquam sollicitudin, dictum id dui. Aliquam efficitur elit ut mi vehicula, sed cursus elit suscipit. Vestibulum quis ligula in est iaculis consectetur a id urna. Phasellus semper in libero non laoreet. Quisque nec tempor tellus. Nullam non nunc magna. Nullam fringilla, libero non euismod semper, est mauris facilisis erat, quis auctor diam dolor sit amet augue. Mauris interdum interdum leo, et pulvinar felis vulputate eget.'
    ];

    console.log(`~~~ [TEST] ~~~`);
    console.log(`>>> Running ${bobToAliceTests.length} BOB >> ALICE Message Tests...`);
    try {
      for (let i=0; i < bobToAliceTests.length; i++) {
        let testMessage = bobToAliceTests[i];
        try {
          let encodedMessage = await bobClient.prepareMessage('userAlice', testMessage).then(bobClient.encodeMessage);
          let plainTextMessage = await aliceClient.decryptEncodedMessage('userBob', encodedMessage);
          console.log({
            test: (i + 1),
            success: (plainTextMessage === testMessage),
            encoded: encodedMessage.substr(0, 20) + '...'
          });
        } catch (err) {
          console.log('BOB >> ALICE ...unable to decrypt message');
          console.log(err);
        }
      }

      console.log('...BOB >> ALICE ...Test complete!');
      console.log('---\n---');
    } catch (err) {
      console.log('...ALICE >> BOB ... FAILED');
      console.log(err);
    }

    console.log(`~~~ [TEST] ~~~`);
    console.log(`>>> Running ${bobToAliceTests.length} ALICE >> BOB Message Tests...`);
    try {
      for (let i=0; i < bobToAliceTests.length; i++) {
        let testMessage = bobToAliceTests[i];
        try {
          let encodedMessage = await aliceClient.prepareMessage('userBob', testMessage).then(aliceClient.encodeMessage);
          let plainTextMessage = await bobClient.decryptEncodedMessage('userAlice', encodedMessage);
          console.log({
            test: (i + 1),
            success: (plainTextMessage === testMessage),
            encoded: encodedMessage.substr(0, 20) + '...'
          });
        } catch (err) {
          console.log('ALICE >> BOB ...unable to decrypt message');
          console.log(err);
        }
      }

      console.log('...ALICE >> BOB ...Test complete!');
      console.log('---\n---');
    } catch (err) {
      console.log('...ALICE >> BOB ... FAILED');
      console.log(err);
    }

    console.log(`~~~ [TEST] ~~~`);
    console.log(`>>> Running ${bobToAliceTests.length} BOB >> ALICE Message Tests...`);
    try {
      for (let i=0; i < bobToAliceTests.length; i++) {
        let testMessage = bobToAliceTests[i];
        try {
          let encodedMessage = await bobClient.prepareMessage('userAlice', testMessage).then(aliceClient.encodeMessage);
          let plainTextMessage = await aliceClient.decryptEncodedMessage('userBob', encodedMessage);
          console.log({
            test: (i + 1),
            success: (plainTextMessage === testMessage),
            encoded: encodedMessage.substr(0, 20) + '...'
          });
        } catch (err) {
          console.log('BOB >> ALICE ...unable to decrypt message');
          console.log(err);
        }
      }

      console.log('...BOB >> ALICE ...Test complete!');
      console.log('---\n---');
    } catch (err) {
      console.log('...ALICE >> BOB ... FAILED');
      console.log(err);
    }

  }

  /**
   * This demo runs through another conversation between ALICE and BOB but
   * provides an example of exporting a client (ALICE) and recreating the
   * ALICE client to continue the conversation
   */
  public async demo_ClientConversationInit() {
    console.log('===- DEMO -- ClientConversation -===');

    /**
     * Generate Alice and Bob clients
     */
    let aliceClient     = new LibsignalProtocol.Client('userAlice', 2222, 123);
    let aliceClientReg  = aliceClient.exportRegistrationObj();

    let bobClient       =  new LibsignalProtocol.Client('userBob', 1111, 123);
    let bobClientReg    = bobClient.exportRegistrationObj();

    /**
     * Generate Alice and Bob bundle stores (ClientInfo)
     */
    let aliceClientInfo = new LibsignalProtocol.ClientInfo(
      aliceClientReg.identityPubKey, aliceClientReg.address.registrationId,
      aliceClientReg.address.deviceId, aliceClientReg.preKeys,
      aliceClientReg.signedPreKey.id, aliceClientReg.signedPreKey.pubKey,
      aliceClientReg.signedPreKey.signature
    );

    let bobClientInfo = new LibsignalProtocol.ClientInfo(
      bobClientReg.identityPubKey, bobClientReg.address.registrationId,
      bobClientReg.address.deviceId, bobClientReg.preKeys,
      bobClientReg.signedPreKey.id, bobClientReg.signedPreKey.pubKey,
      bobClientReg.signedPreKey.signature
    );
    
    /**
     * Test #1
     * 
     * Initial Alice to Bob message
     */
    let testMsg1 = 'HELLO BOB FROM ALICE 1';

    // Alice adds bob bundle
    let bobBundle1 = bobClientInfo.getPreKeyBundle();
    await aliceClient.addSession(bobClientReg.address, bobBundle1);

    // Alice sends message to Bob
    let encodedMessage1 = await aliceClient.prepareMessage(bobClientReg.address.name, testMsg1)
    .then(aliceClient.encodeMessage);

    // Bob sees message from Alice... Pulls bundle for Alice with no previous pull...
    let aliceBundle1 = aliceClientInfo.getPreKeyBundle();
    await bobClient.addSession(aliceClientReg.address, aliceBundle1);

    // Bob decrypts message
    try {
      let plainTextMessage1 = await bobClient.decryptEncodedMessage(aliceClientReg.address.name, encodedMessage1);
    
      console.log('Alice >> Bob', {
        before: testMsg1,
        after: encodedMessage1,
        success: (testMsg1 === plainTextMessage1)
      });
    } catch (err) {
      console.log('Unable to decrypt ALICE >> BOB');
      console.log(err.message ? err.message : err);
    }

    

    
    /**
     * Test #2
     * 
     * Alice has gone offline and is a new session,
     * Bob has sent a message
     * Alice is decrypting the message
     */
    let testMsg2 = 'HELLO ALICE FROM BOB 1';

    // Bob posts a message
    await bobClient.addSession(aliceClientReg.address, aliceClientInfo.getPreKeyBundle());
    let encodedMessage2 = await bobClient.prepareMessage(aliceClientReg.address.name, testMsg2).then(bobClient.encodeMessage);

    // Alice Client imported from saved state
    let importedAliceClient = JSON.parse(JSON.stringify(aliceClient));

    let newAliceClient = new LibsignalProtocol.Client(importedAliceClient.username, importedAliceClient.registrationId, importedAliceClient.deviceId, importedAliceClient.identityKeyPair, importedAliceClient.signedPreKey, importedAliceClient.preKeys);

    // Alice sees a message from Bob, pulls a bob bundle...
    await newAliceClient.addSession(bobClientReg.address, bobClientInfo.getPreKeyBundle());

    // Alice decrypts message
    try {
      let plainTextMessage2 = await newAliceClient.decryptEncodedMessage(bobClientReg.address.name, encodedMessage2);
    
      console.log('Bob >> NewAlice', {
        before: testMsg2,
        after: encodedMessage2,
        success: (testMsg2 === plainTextMessage2)
      });
    } catch (err) {
      console.log('Unable to decrypt BOB >> ALICE');
      console.log(err.message ? err.message : err);
    }

    return true;
  }

  private async pushSessionToServer() {
    console.log("===- PUSH SESSION TO SERVER -===");
    
    let identity: IIdentityKeyPair = await this.memoryState.store.getIdentityKeyPair();

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

    // request({
    //   url: `${API}`,
    //   method: "PUT",
    //   headers: { "Content-Type": "application/json" },
    //   content: JSON.stringify(requestObj)
    // }).then((response) => {
    //   console.log('-- response');
    //   console.dir(response);
    //   console.log('-- content');
    //   console.log(response.content);
    //   console.log('-- content.toJSON');
    //   console.dir(response.content.toJSON());
    // }, (e) => {
    //   console.log('Error occurred');
    //   console.log(e.message ? e.message : e);
    //   console.dir(e);
    // });
  }

  private async sendToServer() {
    console.log("===- SEND TO SERVER -===");
  }

  private async pullFromServer() {
    console.log("===- PULL FROM SERVER -===");
  }
}
