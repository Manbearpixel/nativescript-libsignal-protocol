# NativeScript Libsignal-Protocol ![android-support](https://camo.githubusercontent.com/e77a0a1454be63dbb168e7be9c81c5889ae1b0c8/68747470733a2f2f63646e342e69636f6e66696e6465722e636f6d2f646174612f69636f6e732f6c6f676f732d332f3232382f616e64726f69642d33322e706e67)

 [![Developed for ODIN](https://odin.nyc3.digitaloceanspaces.com/badges/ODIN-Badge-DevelopedFor.png)](https://odinblockchain.org/)

 [![npm version](https://img.shields.io/npm/v/nativescript-libsignal-protocol.svg?colorA=1d2323&colorB=41C0D1&style=flat-square)](https://npmjs.org/package/nativescript-libsignal-protocol) [![license](https://img.shields.io/npm/l/nativescript-libsignal-protocol.svg?colorA=1d2323&colorB=41C0D1&style=flat-square)](https://choosealicense.com/licenses/gpl-3.0/)



[![NPM](https://nodei.co/npm/nativescript-libsignal-protocol.png?downloads=true)](https://nodei.co/npm/nativescript-libsignal-protocol/)



This plugin is a Libsiginal Protocol implementation for NativeScript and is based on [libsignal-protocol-java](https://github.com/signalapp/libsignal-protocol-java). This plugin is currently a wrapper which implements functionality developed by The Open Whisper Systems organization, the active maintainers behind the encrypted messenger application Signal.

**This plugin is currently in ALPHA stages and will require additional work to mature. This code has NOT been reviewed by an experienced cryptopgrapher so usage and support cannot be guarenteed at this time.**



## Requirements

This plugin requires no additional permissions to work properly. The application implementing this plugin however, will likely require `android.permission.INTERNET` if you are using a central server to manage data.



## Installation

```bash
$ tns plugin add nativescript-libsignal-protocol
```



## Usage

Importing `LibsignalProtocol` from this plugin will allow you to use various classes and implementation wrappers that are currently available. Numerous type definitions have been created to your IDE to provide context to various pieces so far made available. The demo application provided with this plugin contains a couple different examples of using this plugin for a project.

This plugin follows the same implementation and usage standards which can be found from the sourcecode Github Repository. Listed below is simple snippet demonstrating usage.



```typescript
import { LibsignalProtocol } from 'nativescript-libsignal-protocol';

const SignalKeyHelper = LibsignalProtocol.KeyHelper;
const Base64Encode = LibsignalProtocol.Util.base64Encode;

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
```



## Limitations

This plugin is currently not available for iOS devices (Contributions for iOS support are welcomed and desired!). This plugin is also meant to be a simple wapper for using the Libsignal Protocol. While this plugin contains a `Client` class for storing a session/state, the actual use and management should be taken care of within the application using this plugin.



## License

Licensed under the GPLv3: <http://www.gnu.org/licenses/gpl-3.0.html>

- Copyright 2015-2016 Open Whisper Systems
- Copyright 2018-2019 @Pixxlated



## Acknowledgements

This plugin contains source code based on the following:

| **libsignal-protocol-java** | https://github.com/signalapp/libsignal-protocol-java |
| --------------------------- | ---------------------------------------------------- |
|                             |                                                      |

Special thanks to the original contributors and authors of the works above!
