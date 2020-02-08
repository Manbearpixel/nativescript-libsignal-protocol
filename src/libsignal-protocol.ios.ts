/// <reference path="node_modules/tns-platform-declarations/ios.d.ts" />

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

export namespace LibsignalProtocol {
  export class KeyHelper implements KeyHelperDef {
    public static generateRegistrationId(extendedRange?: boolean): number {
      throw "Not implemented";
    }
  }
}


