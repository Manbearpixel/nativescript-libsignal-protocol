import { LibsignalProtocol } from 'nativescript-libsignal-protocol';

const SignalCore = LibsignalProtocol.Core;
const SignalUtil = LibsignalProtocol.Util;
const SignalCurve = LibsignalProtocol.Curve;

export default class TestCore {
  BOB_ADDRESS: LibsignalProtocol.Type.SignalProtocolAddress;
  ALICE_ADDRESS: LibsignalProtocol.Type.SignalProtocolAddress;

  aliceSignedPreKey: LibsignalProtocol.Type.ECKeyPair;
  bobSignedPreKey: LibsignalProtocol.Type.ECKeyPair;

  aliceSignedPreKeyId: number;
  bobSignedPreKeyId: number;

  aliceStore: LibsignalProtocol.Interface.ISignalProtocolStore;
  bobStore: LibsignalProtocol.Interface.ISignalProtocolStore;
  
  constructor() {
    this.BOB_ADDRESS    = SignalCore.createSignalProtocolAddress(1111, 1);
    this.ALICE_ADDRESS  = SignalCore.createSignalProtocolAddress(2222, 1);

    this.aliceStore     = SignalCore.createTestSignalProtocolStore();
    this.bobStore       = SignalCore.createTestSignalProtocolStore();

    this.aliceSignedPreKey  = SignalCurve.generateKeyPair();
    this.bobSignedPreKey    = SignalCurve.generateKeyPair();

    this.aliceSignedPreKeyId  = new java.util.Random().nextInt(0xFFFFFF);
    this.bobSignedPreKeyId    = new java.util.Random().nextInt(0xFFFFFF);

    console.log(
      'aliceReg',
      this.aliceStore.getLocalRegistrationId(),
      this.ALICE_ADDRESS.getName()
    );

    console.log(
      'bobReg',
      this.bobStore.getLocalRegistrationId(),
      this.BOB_ADDRESS.getName()
    );

    console.log('--- TestCore Created ---');
  }

  public testBasicSimultaneousInitiate(): void {
    console.log('--- TestCore::Running ---');

    let alice_unsignedKeyPair = SignalCurve.generateKeyPair();
    let alice_unsignedKeyPairId = new java.util.Random().nextInt(0xFFFFFF);
    let alicebundle = this.generatePreKeyBundle(this.aliceStore, this.aliceSignedPreKeyId, this.aliceSignedPreKey, alice_unsignedKeyPairId, alice_unsignedKeyPair);

    let alicePreKeyBundle1 = this.importPreKeyBundle(
      alicebundle,
      this.ALICE_ADDRESS
    );

    let bobPreKeyBundle1 = this.importPreKeyBundle(
      this.generatePreKeyBundle(this.bobStore, this.bobSignedPreKeyId, this.bobSignedPreKey),
      this.BOB_ADDRESS
    );
    console.log('--- TestCore::Bundles Created ---');

    // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
    let aliceSessionBuilder = SignalCore.createSessionBuilder(this.aliceStore, this.BOB_ADDRESS);
    let bobSessionBuilder   = SignalCore.createSessionBuilder(this.bobStore, this.ALICE_ADDRESS);
    console.log('--- TestCore::Sessions Built ---');

    // Build a session with a PreKey retrieved from the server.
    aliceSessionBuilder.process(bobPreKeyBundle1);
    bobSessionBuilder.process(alicePreKeyBundle1);
    console.log('--- TestCore::Sessions Exchanged ---');

    let aliceSessionCipher  = SignalCore.createSessionCipher(this.aliceStore, this.BOB_ADDRESS);
    let bobSessionCipher    = SignalCore.createSessionCipher(this.bobStore, this.ALICE_ADDRESS);
    console.log('--- TestCore::Ciphers Created ---');

    let bobMessage    = new java.lang.String("hey there");
    let aliceMessage  = new java.lang.String("sample message");

    let messageForBob: LibsignalProtocol.Type.CiphertextMessage   = aliceSessionCipher.encrypt(bobMessage.getBytes("UTF-8"));
    let messageForAlice: LibsignalProtocol.Type.CiphertextMessage = bobSessionCipher.encrypt(aliceMessage.getBytes("UTF-8"));
    console.log('--- TestCore::Encrypted ---');

    console.log({
      recipient: 'bob',
      msg: bobMessage.toString(),
      encrypted: SignalUtil.base64Encode(messageForBob.serialize())
    });

    console.log({
      recipient: 'alice',
      msg: aliceMessage.toString(),
      encrypted: SignalUtil.base64Encode(messageForAlice.serialize())
    });

    let bobPlaintext   = bobSessionCipher.decrypt(
      SignalCore.createPreKeySignalMessage(messageForBob.serialize())
    );

    let alicePlaintext = aliceSessionCipher.decrypt(
      SignalCore.createPreKeySignalMessage(messageForAlice.serialize())
    );
    console.log('--- TestCore::Decryption ---');

    console.log({
      recipient: 'bob',
      msg: bobMessage.toString(),
      encrypted: SignalUtil.base64Encode(messageForBob.serialize()),
      decrypted: new java.lang.String(bobPlaintext).toString(),
      matched: new java.lang.String(bobPlaintext).equals("hey there")
    });
    
    console.log({
      who: 'alice',
      msg: aliceMessage.toString(),
      encrypted: SignalUtil.base64Encode(messageForAlice.serialize()),
      decrypted: new java.lang.String(alicePlaintext).toString(),
      matches: new java.lang.String(alicePlaintext).equals("sample message")
    });
  }

  private importPreKeyBundle(importedData: any, address: LibsignalProtocol.Type.SignalProtocolAddress): LibsignalProtocol.PreKeyBundle {
    let identityPubKey = SignalCore.importIdentityKey(SignalUtil.base64Decode(importedData.identityPubKey));

    return SignalCore.createPreKeyBundle(
      Number(address.getName()),
      Number(address.getDeviceId()),
      importedData.preKeyRecordId,
      SignalCore.importPublicKey(SignalUtil.base64Decode(importedData.preKeyPublic)),
      importedData.signedPreKeyRecordId,
      SignalCore.importPublicKey(SignalUtil.base64Decode(importedData.signedPreKeyPublic)),
      SignalUtil.base64Decode(importedData.signature),
      identityPubKey
    );
  }

  private generatePreKeyBundle(signalStore: LibsignalProtocol.Interface.ISignalProtocolStore, signedPreKeyId: number, signedPreKeyPair: LibsignalProtocol.Type.ECKeyPair, unsignedKeyPairId?: number, unsignedKeyPair?: LibsignalProtocol.Type.ECKeyPair): any {
    if (typeof unsignedKeyPair === 'undefined')
      unsignedKeyPair = SignalCurve.generateKeyPair();
    
    if (typeof unsignedKeyPairId === 'undefined')
      unsignedKeyPairId = new java.util.Random().nextInt(0xFFFFFF);
    
    let bundleSignature: any = SignalCurve.calculateSignature(
      signalStore.getIdentityKeyPair().getPrivateKey(),
      signedPreKeyPair.getPublicKey().serialize()
    );

    let signedPreKeyRecord = SignalCore.createSignedPreKeyRecord(
      signedPreKeyId, java.lang.System.currentTimeMillis(), signedPreKeyPair, bundleSignature
    );
    signalStore.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);

    let preKeyRecord = SignalCore.createPreKeyRecord(
      unsignedKeyPairId, unsignedKeyPair
    );
    signalStore.storePreKey(unsignedKeyPairId, preKeyRecord);

    return {
      preKeyPublic: SignalUtil.base64Encode(unsignedKeyPair.getPublicKey().serialize()),
      preKeyRecordId: unsignedKeyPairId,
      signedPreKeyPublic: SignalUtil.base64Encode(signedPreKeyPair.getPublicKey().serialize()),
      signedPreKeyRecordId: signedPreKeyId,
      signature: SignalUtil.base64Encode(bundleSignature),
      identityPubKey: SignalUtil.base64Encode(signalStore.getIdentityKeyPair().getPublicKey().serialize())
    };
  }
}
