package com.sfe.sign.signing;

record Pkcs11Readiness(boolean libraryAvailable, boolean moduleReady) {

    static Pkcs11Readiness unavailable() {
        return new Pkcs11Readiness(false, false);
    }
}

