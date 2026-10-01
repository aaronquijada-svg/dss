package com.sfe.sign.signing;

interface Pkcs11ReadinessProbe {

    Pkcs11Readiness inspect(String libraryPath);
}

