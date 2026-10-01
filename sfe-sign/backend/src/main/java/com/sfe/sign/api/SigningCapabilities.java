package com.sfe.sign.api;

import java.util.List;

public record SigningCapabilities(
        String provider,
        boolean providerConfigured,
        boolean pkcs11LibraryAvailable,
        boolean pkcs11ModuleReady,
        boolean tsaConfigured,
        List<SignatureMode> supportedModes) {
}
