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
class LocalAgentSigningProvider implements SigningProvider {
    private final LocalAgentClient localAgentClient;

    LocalAgentSigningProvider(LocalAgentClient localAgentClient) {
        this.localAgentClient = localAgentClient;
    }

    @Override
    public SigningCapabilities capabilities() {
        return new SigningCapabilities(
                "SafeSign PKCS#11 (local agent)",
                localAgentClient.configured(),
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
                "The local SafeSign agent is configured. Use the local PAdES workflow to request desktop approval.");
    }
}
