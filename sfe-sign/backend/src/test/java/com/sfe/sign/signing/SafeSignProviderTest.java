package com.sfe.sign.signing;

import static org.assertj.core.api.Assertions.assertThat;

import com.sfe.sign.api.SigningCapabilities;
import com.sfe.sign.config.SigningProperties;
import org.junit.jupiter.api.Test;

class SafeSignProviderTest {

    @Test
    void exposesOnlyReadinessWhenSafeSignIsConfigured() {
        SigningProperties properties = new SigningProperties();
        properties.setSigningProvider(SigningProperties.SigningProviderType.SAFESIGN);
        properties.setPkcs11LibraryPath("C:\\Windows\\System32\\aetpkss1.dll");
        Pkcs11ReadinessProbe probe = ignored -> new Pkcs11Readiness(true, true);

        SigningCapabilities capabilities = new SafeSignProvider(properties, probe).capabilities();

        assertThat(capabilities.providerConfigured()).isTrue();
        assertThat(capabilities.pkcs11LibraryAvailable()).isTrue();
        assertThat(capabilities.pkcs11ModuleReady()).isTrue();
        assertThat(capabilities.toString()).doesNotContain("aetpkss1.dll");
    }

    @Test
    void doesNotProbeWhenSafeSignIsNotConfigured() {
        SigningProperties properties = new SigningProperties();
        Pkcs11ReadinessProbe probe = ignored -> {
            throw new AssertionError("PKCS#11 must not be probed when not configured");
        };

        SigningCapabilities capabilities = new SafeSignProvider(properties, probe).capabilities();

        assertThat(capabilities.providerConfigured()).isFalse();
        assertThat(capabilities.pkcs11LibraryAvailable()).isFalse();
        assertThat(capabilities.pkcs11ModuleReady()).isFalse();
    }

    @Test
    void reportsTheLocalAgentAsTheConfiguredSafeSignProvider() {
        SigningProperties properties = new SigningProperties();
        properties.setAgentUrl("http://127.0.0.1:12345");
        properties.setAgentSessionSecret("ephemeral-session-secret");

        SigningCapabilities capabilities = new LocalAgentSigningProvider(new LocalAgentClient(properties)).capabilities();

        assertThat(capabilities.provider()).isEqualTo("SafeSign PKCS#11 (local agent)");
        assertThat(capabilities.providerConfigured()).isTrue();
        assertThat(capabilities.pkcs11ModuleReady()).isFalse();
    }
}
