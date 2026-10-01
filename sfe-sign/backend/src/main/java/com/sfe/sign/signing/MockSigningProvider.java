package com.sfe.sign.signing;

import com.sfe.sign.api.SignatureMode;
import com.sfe.sign.api.SignatureRequest;
import com.sfe.sign.api.SignatureResponse;
import com.sfe.sign.api.SignatureStatus;
import com.sfe.sign.api.SigningCapabilities;
import java.util.Arrays;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class MockSigningProvider implements SigningProvider {

    @Override
    public SigningCapabilities capabilities() {
        return new SigningCapabilities(
                "Mock",
                false,
                false,
                false,
                false,
                Arrays.asList(SignatureMode.values()));
    }

    @Override
    public SignatureResponse prepare(SignatureRequest request) {
        return new SignatureResponse(
                UUID.randomUUID(),
                SignatureStatus.PENDING_CONFIGURATION,
                "No signing provider is configured. Select SafeSign PKCS#11 only after an approved signing ceremony is available.");
    }
}
