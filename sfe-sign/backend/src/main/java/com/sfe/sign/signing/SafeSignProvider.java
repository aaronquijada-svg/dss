package com.sfe.sign.signing;

import com.sfe.sign.api.SignatureMode;
import com.sfe.sign.api.SignatureRequest;
import com.sfe.sign.api.SignatureResponse;
import com.sfe.sign.api.SignatureStatus;
import com.sfe.sign.api.SigningCapabilities;
import com.sfe.sign.config.SigningProperties;
import java.util.Arrays;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class SafeSignProvider implements SigningProvider {

    private final SigningProperties properties;
    private final Pkcs11ReadinessProbe readinessProbe;

    public SafeSignProvider(SigningProperties properties, Pkcs11ReadinessProbe readinessProbe) {
        this.properties = properties;
        this.readinessProbe = readinessProbe;
    }

    @Override
    public SigningCapabilities capabilities() {
        boolean configured = properties.getSigningProvider() == SigningProperties.SigningProviderType.SAFESIGN
                && StringUtils.hasText(properties.getPkcs11LibraryPath());
        Pkcs11Readiness readiness = configured
                ? readinessProbe.inspect(properties.getPkcs11LibraryPath())
                : Pkcs11Readiness.unavailable();
        return new SigningCapabilities(
                "SafeSign PKCS#11",
                configured,
                readiness.libraryAvailable(),
                readiness.moduleReady(),
                StringUtils.hasText(properties.getTsaUrl()),
                Arrays.asList(SignatureMode.values()));
    }

    @Override
    public SignatureResponse prepare(SignatureRequest request) {
        return new SignatureResponse(
                UUID.randomUUID(),
                SignatureStatus.PENDING_CONFIGURATION,
                "SafeSign signing is not enabled in this starter. Configure an approved signing ceremony without PIN persistence.");
    }
}
