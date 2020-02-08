import { KeyHelperDef } from './libsignal-protocol.common';

export namespace LibsignalProtocol {
  export class KeyHelper implements KeyHelperDef {
    public static generateRegistrationId(extendedRange?: boolean): number {
      throw "Not implemented";
    }
  }
}


