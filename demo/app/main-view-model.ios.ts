import { Observable } from 'tns-core-modules/data/observable';
import { LibsignalProtocol } from 'nativescript-libsignal-protocol';
// import { Couchbase } from 'nativescript-couchbase-plugin';
// import TestCore from './test-core';

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

  constructor() {
    super();
    
    // uncomment to clear application setting storage
    // clear();

    // output LibsignalProtocol available classes
    console.log('===- LibsignalProtocol -===');
    console.dir(LibsignalProtocol);
  }
}
