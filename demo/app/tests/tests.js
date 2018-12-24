var LibsignalProtocol = require("nativescript-libsignal-protocol").LibsignalProtocol;
var libsignalProtocol = new LibsignalProtocol();

describe("greet function", function() {
    it("exists", function() {
        expect(libsignalProtocol.greet).toBeDefined();
    });

    it("returns a string", function() {
        expect(libsignalProtocol.greet()).toEqual("Hello, NS");
    });
});