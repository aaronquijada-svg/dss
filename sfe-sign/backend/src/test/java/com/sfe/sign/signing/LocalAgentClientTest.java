package com.sfe.sign.signing;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LocalAgentClientTest {

    @Test
    void exposesActionableSafeSignSlotGuidanceWithoutNativeDetails() {
        String message = LocalAgentClient.agentFailureMessage(
                "PKCS11_SLOT_UNAVAILABLE", "opening SafeSign PKCS#11");

        assertThat(message)
                .contains("PKCS11_SLOT_UNAVAILABLE")
                .contains("reader, inserted card, SafeSign middleware")
                .doesNotContain("aetpkss1.dll");
    }
}
