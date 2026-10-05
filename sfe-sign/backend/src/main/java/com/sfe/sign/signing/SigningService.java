package com.sfe.sign.signing;

import com.sfe.sign.api.SignatureRequest;
import com.sfe.sign.api.SignatureResponse;
import com.sfe.sign.api.SigningCapabilities;
import com.sfe.sign.config.SigningProperties;
import org.springframework.stereotype.Service;

@Service
public class SigningService {

    private final SigningProvider mockSigningProvider;
    private final SigningProvider safeSignProvider;
    private final SigningProvider localAgentSigningProvider;
    private final LocalAgentClient localAgentClient;
    private final SigningProperties properties;

    public SigningService(
            MockSigningProvider mockSigningProvider,
            SafeSignProvider safeSignProvider,
            LocalAgentSigningProvider localAgentSigningProvider,
            LocalAgentClient localAgentClient,
            SigningProperties properties) {
        this.mockSigningProvider = mockSigningProvider;
        this.safeSignProvider = safeSignProvider;
        this.localAgentSigningProvider = localAgentSigningProvider;
        this.localAgentClient = localAgentClient;
        this.properties = properties;
    }

    public SigningCapabilities capabilities() {
        return selectedProvider().capabilities();
    }

    public SignatureResponse prepare(SignatureRequest request) {
        DssPadesProfile.baselineLt();
        return selectedProvider().prepare(request);
    }

    private SigningProvider selectedProvider() {
        if (localAgentClient.configured()) {
            return localAgentSigningProvider;
        }
        return properties.getSigningProvider() == SigningProperties.SigningProviderType.SAFESIGN
                ? safeSignProvider
                : mockSigningProvider;
    }
}
