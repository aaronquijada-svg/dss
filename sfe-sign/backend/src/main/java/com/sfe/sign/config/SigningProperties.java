package com.sfe.sign.config;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "sfe-sign")
public class SigningProperties {

    @NotNull
    private SigningProviderType signingProvider = SigningProviderType.MOCK;

    private String pkcs11LibraryPath;

    @ValidTsaUri
    private String tsaUrl;
    private int pkcs11Slot;
    private String agentUrl;
    private String agentSessionSecret;

    public SigningProviderType getSigningProvider() {
        return signingProvider;
    }

    public void setSigningProvider(SigningProviderType signingProvider) {
        this.signingProvider = signingProvider;
    }

    public String getPkcs11LibraryPath() {
        return pkcs11LibraryPath;
    }

    public void setPkcs11LibraryPath(String pkcs11LibraryPath) {
        this.pkcs11LibraryPath = pkcs11LibraryPath;
    }

    public String getTsaUrl() {
        return tsaUrl;
    }

    public void setTsaUrl(String tsaUrl) {
        this.tsaUrl = tsaUrl;
    }
    public int getPkcs11Slot() { return pkcs11Slot; }
    public void setPkcs11Slot(int pkcs11Slot) { this.pkcs11Slot = pkcs11Slot; }
    public String getAgentUrl() { return agentUrl; }
    public void setAgentUrl(String agentUrl) { this.agentUrl = agentUrl; }
    public String getAgentSessionSecret() { return agentSessionSecret; }
    public void setAgentSessionSecret(String agentSessionSecret) { this.agentSessionSecret = agentSessionSecret; }

    public enum SigningProviderType {
        MOCK,
        SAFESIGN
    }
}
